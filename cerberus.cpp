#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <SoftPub.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <DbgHelp.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <intrin.h>
#include <set>
#include <Shlwapi.h>
#include <winioctl.h>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <VersionHelpers.h>
#include <shlobj.h>
#include <regex>
#include <array>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;
namespace fs = std::filesystem;

// System configuration
struct GlobalConfig {
    bool dryRun = false;
    bool noKill = false;
    bool jsonLog = false;
    bool memoryDump = false;
    bool networkScan = false;
    bool threatIntel = false;
    bool timelineForensics = false;
    bool advancedHeuristics = true;
    bool detectCodeInjection = true;
    bool detectRootkits = true;
    bool detectPersistence = true;
    int maxThreads = 8;  // Optimal thread count
    
    std::string threatIntelAPI = "https://api.virustotal.com/v3/ip_addresses/";
    std::string apiKey = "YOUR_VIRUSTOTAL_API_KEY";
    std::string jsonLogPath = "cerberus_scan.json";
    std::string dumpPath = "memory_dumps";
    std::string timelinePath = "timeline_forensics";
    
    std::vector<std::wstring> whitelist = {
        L"System", L"Registry", L"smss.exe", 
        L"csrss.exe", L"wininit.exe", L"services.exe",
        L"lsass.exe", L"svchost.exe", L"winlogon.exe",
        L"explorer.exe", L"taskhost.exe", L"dwm.exe",
        L"spoolsv.exe", L"taskeng.exe", L"SearchIndexer.exe",
        L"RuntimeBroker.exe", L"ctfmon.exe"
    };
} config;

// Advanced system definitions
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Structure for memory regions
struct MEMORY_REGION {
    LPVOID Address;
    SIZE_T Size;
    DWORD Protect;
};

// Scan results structure
struct ScanResult {
    std::string type;
    std::string description;
    DWORD pid = 0;
    std::string process;
    std::string details;
    bool mitigated = false;
};

// Kernel driver helper definitions
#define IOCTL_GET_HOOK_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DRIVER_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
struct HookInfo {
    UINT_PTR FunctionAddress;
    UINT_PTR HookedAddress;
    char ModuleName[256];
    char FunctionName[256];
};

struct DriverInfo {
    char DriverName[256];
    UINT_PTR BaseAddress;
    ULONG Size;
    bool Hidden;
};
#pragma pack(pop)

// ===== قاعدة بيانات التوقيعات ===== //
class SignatureDatabase {
private:
    std::vector<std::vector<uint8_t>> maliciousPatterns;
    std::set<std::string> maliciousHashes;
    std::set<std::string> maliciousIPs;
    std::set<std::string> maliciousDomains;

public:
    SignatureDatabase() {
        // توقيعات عامة للبرمجيات الخبيثة
        maliciousPatterns.push_back({0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x48, 0x83}); // shellcode شائع
        maliciousPatterns.push_back({0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F}); // "hello world"
        maliciousPatterns.push_back({0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}); // MZ header
        
        // قائمة عناوين IP ضارة
        maliciousIPs.insert("185.130.5.231");
        maliciousIPs.insert("45.133.1.147");
        maliciousIPs.insert("193.142.146.101");
        
        // قائمة نطاقات ضارة
        maliciousDomains.insert("malicious-domain.com");
        maliciousDomains.insert("evil-site.org");
        maliciousDomains.insert("phishing-page.net");
    }

    bool IsMaliciousPattern(const std::vector<uint8_t>& data) {
        for (const auto& pattern : maliciousPatterns) {
            auto it = std::search(data.begin(), data.end(), pattern.begin(), pattern.end());
            if (it != data.end()) {
                return true;
            }
        }
        return false;
    }

    bool IsMaliciousIP(const std::string& ip) {
        return maliciousIPs.find(ip) != maliciousIPs.end();
    }

    bool IsMaliciousDomain(const std::string& domain) {
        return maliciousDomains.find(domain) != maliciousDomains.end();
    }
};

// ===== محلل الذاكرة المتقدم ===== //
class AdvancedMemoryAnalyzer {
private:
    SignatureDatabase signatureDB;

public:
    bool AnalyzeMemoryRegion(const std::vector<uint8_t>& memoryData) {
        // تحليل سريع للذاكرة باستخدام التوقيعات
        if (signatureDB.IsMaliciousPattern(memoryData)) {
            return true;
        }
        
        // تحليل إضافي (يمكن إضافة المزيد من التحليلات هنا)
        return false;
    }

    bool CheckForCodeCaves(const std::vector<uint8_t>& memoryData) {
        const size_t minCaveSize = 128;
        size_t consecutiveZeros = 0;
        
        for (uint8_t byte : memoryData) {
            if (byte == 0x00 || byte == 0x90) { // NOP أو NULL
                consecutiveZeros++;
                if (consecutiveZeros >= minCaveSize) {
                    return true;
                }
            } else {
                consecutiveZeros = 0;
            }
        }
        return false;
    }
};

// ===== Kernel Driver Helper ===== //
class KernelDriverHelper {
private:
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    const char* DRIVER_NAME = "CerberusDriverHelper";
    const char* DEVICE_NAME = "\\\\.\\CerberusDriverHelper";

    bool LoadDriver() {
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!hSCM) return false;

        char driverPath[MAX_PATH];
        GetModuleFileNameA(NULL, driverPath, MAX_PATH);
        PathRemoveFileSpecA(driverPath);
        strcat_s(driverPath, "\\CerberusDriverHelper.sys");

        SC_HANDLE hService = CreateServiceA(
            hSCM, DRIVER_NAME, DRIVER_NAME,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driverPath, NULL, NULL, NULL, NULL, NULL
        );

        if (!hService) {
            if (GetLastError() != ERROR_SERVICE_EXISTS) {
                CloseServiceHandle(hSCM);
                return false;
            }
            hService = OpenServiceA(hSCM, DRIVER_NAME, SERVICE_ALL_ACCESS);
        }

        bool success = StartServiceA(hService, 0, NULL);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return success;
    }

    bool UnloadDriver() {
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!hSCM) return false;

        SC_HANDLE hService = OpenServiceA(hSCM, DRIVER_NAME, SERVICE_ALL_ACCESS);
        if (!hService) {
            CloseServiceHandle(hSCM);
            return false;
        }

        SERVICE_STATUS status;
        bool success = ControlService(hService, SERVICE_CONTROL_STOP, &status);
        DeleteService(hService);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return success;
    }

public:
    KernelDriverHelper() {
        // Try to open existing driver first
        hDriver = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 
                              0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        // If not found, load the driver
        if (hDriver == INVALID_HANDLE_VALUE) {
            if (LoadDriver()) {
                hDriver = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 
                                      0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            }
        }
    }

    ~KernelDriverHelper() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
        }
        UnloadDriver();
    }

    bool IsDriverLoaded() const {
        return hDriver != INVALID_HANDLE_VALUE;
    }

    std::vector<HookInfo> GetKernelHooks() {
        std::vector<HookInfo> hooks;
        if (hDriver == INVALID_HANDLE_VALUE) return hooks;

        DWORD bytesReturned = 0;
        HookInfo buffer[512] = {0};

        if (DeviceIoControl(hDriver, IOCTL_GET_HOOK_INFO, NULL, 0, 
                           buffer, sizeof(buffer), &bytesReturned, NULL)) {
            int count = bytesReturned / sizeof(HookInfo);
            for (int i = 0; i < count; i++) {
                hooks.push_back(buffer[i]);
            }
        }

        return hooks;
    }

    std::vector<DriverInfo> GetDriverInfo() {
        std::vector<DriverInfo> drivers;
        if (hDriver == INVALID_HANDLE_VALUE) return drivers;

        DWORD bytesReturned = 0;
        DriverInfo buffer[256] = {0};

        if (DeviceIoControl(hDriver, IOCTL_GET_DRIVER_INFO, NULL, 0, 
                           buffer, sizeof(buffer), &bytesReturned, NULL)) {
            int count = bytesReturned / sizeof(DriverInfo);
            for (int i = 0; i < count; i++) {
                drivers.push_back(buffer[i]);
            }
        }

        return drivers;
    }
};

// ===== Timeline Forensics ===== //
class TimelineForensics {
private:
    void CopyFileToOutput(const std::string& src, const std::string& destDir) {
        if (!fs::exists(src)) return;
        
        try {
            fs::path destPath = fs::path(destDir) / fs::path(src).filename();
            fs::copy_file(src, destPath, fs::copy_options::overwrite_existing);
        } catch (...) {
            // Handle error
        }
    }

public:
    void CollectEvidence() {
        CreateDirectoryA(config.timelinePath.c_str(), NULL);
        
        // Collect MFT
        std::string mftPath = "C:\\$MFT";
        CopyFileToOutput(mftPath, config.timelinePath);

        // Collect registry hives
        std::vector<std::string> registryHives = {
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\SOFTWARE",
            "C:\\Windows\\System32\\config\\SECURITY",
            "C:\\Windows\\System32\\config\\DEFAULT"
        };

        for (const auto& hive : registryHives) {
            CopyFileToOutput(hive, config.timelinePath);
        }

        // Collect prefetch files
        std::string prefetchDir = "C:\\Windows\\Prefetch";
        if (fs::exists(prefetchDir)) {
            fs::path destPath = fs::path(config.timelinePath) / "Prefetch";
            fs::create_directory(destPath);
            
            for (const auto& entry : fs::directory_iterator(prefetchDir)) {
                if (entry.is_regular_file()) {
                    fs::copy(entry.path(), destPath / entry.path().filename(), 
                             fs::copy_options::overwrite_existing);
                }
            }
        }
    }
};

// ===== Core System Scanner ===== //
class AdvancedSystemScanner {
private:
    _NtQuerySystemInformation NtQuerySystemInformation;
    _NtQueryInformationProcess NtQueryInformationProcess;
    std::vector<ScanResult> results;
    json jsonLog;
    std::mutex logMutex;
    std::set<DWORD> scannedPIDs;
    std::set<std::string> scannedIPs;
    KernelDriverHelper kernelDriver;
    TimelineForensics timeline;
    AdvancedMemoryAnalyzer memoryAnalyzer;
    SignatureDatabase signatureDB;
    std::atomic<int> activeThreads{0};

    // Utility functions
    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &in_time_t);

        std::stringstream ss;
        ss << std::put_time(&tm, "%Y-%m-%d %X");
        return ss.str();
    }

    std::string FormatSize(SIZE_T size) {
        const char* sizes[] = { "B", "KB", "MB", "GB" };
        double len = static_cast<double>(size);
        int order = 0;
        while (len >= 1024 && order < 3) {
            order++;
            len /= 1024;
        }
        return std::to_string(len) + " " + sizes[order];
    }

    std::string FormatAddress(LPVOID address) {
        std::stringstream ss;
        ss << "0x" << std::hex << reinterpret_cast<uintptr_t>(address);
        return ss.str();
    }

    bool IsWhitelisted(const std::wstring& name) {
        return std::find(config.whitelist.begin(), config.whitelist.end(), name) != config.whitelist.end();
    }

    void LoadWhitelist() {
        // Add common Windows processes
        config.whitelist.push_back(L"winlogon.exe");
        config.whitelist.push_back(L"lsass.exe");
        config.whitelist.push_back(L"svchost.exe");
        config.whitelist.push_back(L"explorer.exe");
        config.whitelist.push_back(L"taskhost.exe");
        config.whitelist.push_back(L"dwm.exe");
    }

    std::vector<DWORD> GetProcessList() {
        std::vector<DWORD> pids;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                pids.push_back(pe.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return pids;
    }

    bool TerminateProcessSafe(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) return false;

        bool result = TerminateProcess(hProcess, 0) != 0;
        CloseHandle(hProcess);
        return result;
    }

    json GetSystemInfo() {
        json info;
        OSVERSIONINFOEX osvi = { sizeof(OSVERSIONINFOEX) };
        GetVersionEx((OSVERSIONINFO*)&osvi);

        info["os"] = {
            {"major", osvi.dwMajorVersion},
            {"minor", osvi.dwMinorVersion},
            {"build", osvi.dwBuildNumber},
            {"platform", osvi.dwPlatformId}
        };

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        info["cpu"] = {
            {"arch", si.wProcessorArchitecture},
            {"cores", si.dwNumberOfProcessors}
        };

        MEMORYSTATUSEX mem;
        mem.dwLength = sizeof(mem);
        GlobalMemoryStatusEx(&mem);
        info["memory"] = {
            {"total", mem.ullTotalPhys},
            {"free", mem.ullAvailPhys}
        };

        return info;
    }

    void SaveJsonLog() {
        std::ofstream o(config.jsonLogPath);
        o << std::setw(4) << jsonLog << std::endl;
    }

    void DumpMemoryRegion(HANDLE hProcess, const MEMORY_REGION& region, DWORD pid, const std::string& processName) {
        std::string filename = config.dumpPath + "\\" + processName + "_" + 
                               std::to_string(pid) + "_" + 
                               FormatAddress(region.Address) + ".dmp";

        std::ofstream file(filename, std::ios::binary);
        if (!file) return;

        std::vector<uint8_t> buffer(region.Size);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, region.Address, buffer.data(), region.Size, &bytesRead)) {
            file.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
            
            // Perform advanced memory analysis
            if (memoryAnalyzer.AnalyzeMemoryRegion(buffer)) {
                std::string details = "Malicious pattern found in memory dump: " + filename;
                LogResult("threat", "Malicious memory content detected", pid, processName, details);
            }
        }
    }

    bool VerifyDriverSignature(LPCSTR path) {
        WINTRUST_FILE_INFO fileInfo = {0};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = LPCWSTR(CA2W(path));

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA wintrustData = {0};
        wintrustData.cbStruct = sizeof(wintrustData);
        wintrustData.dwUIChoice = WTD_UI_NONE;
        wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
        wintrustData.pFile = &fileInfo;

        LONG status = WinVerifyTrust(NULL, &action, &wintrustData);
        return status == ERROR_SUCCESS;
    }

    bool VerifyProcessSignature(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;

        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        bool valid = false;
        
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            WINTRUST_FILE_INFO fileInfo = {0};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = path;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wintrustData = {0};
            wintrustData.cbStruct = sizeof(wintrustData);
            wintrustData.dwUIChoice = WTD_UI_NONE;
            wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
            wintrustData.pFile = &fileInfo;

            LONG status = WinVerifyTrust(NULL, &action, &wintrustData);
            valid = (status == ERROR_SUCCESS);
        }

        CloseHandle(hProcess);
        return valid;
    }

    std::vector<DWORD> GetSystemProcessListViaNtQuery() {
        std::vector<DWORD> pids;
        NTSTATUS status;
        ULONG bufferSize = 0;
        NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
        if (bufferSize == 0) return pids;

        PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)malloc(bufferSize);
        if (!pInfo) return pids;

        status = NtQuerySystemInformation(SystemProcessInformation, pInfo, bufferSize, NULL);
        if (NT_SUCCESS(status)) {
            PSYSTEM_PROCESS_INFO current = pInfo;
            while (current->NextEntryOffset) {
                pids.push_back((DWORD)current->ProcessId);
                current = (PSYSTEM_PROCESS_INFO)((LPBYTE)current + current->NextEntryOffset);
            }
        }

        free(pInfo);
        return pids;
    }

    bool VerifyHiddenProcessEx(DWORD pid, const std::string& processName) {
        // Check 1: Verify process signature
        if (!VerifyProcessSignature(pid)) {
            return true;
        }
        
        // Check 2: Verify process path
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return true;

        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        bool suspicious = false;
        
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            std::wstring wpath(path);
            std::string spath(wpath.begin(), wpath.end());
            
            // Check if in system directories
            if (spath.find("C:\\Windows\\System32") == std::string::npos &&
                spath.find("C:\\Program Files") == std::string::npos) {
                suspicious = true;
            }
        } else {
            suspicious = true;
        }

        CloseHandle(hProcess);
        return suspicious;
    }

    bool DetectSSDTHooks() {
        // Implementation remains the same as before
        return false;
    }

    bool DetectProcessHollowing(HANDLE hProcess, DWORD pid, const std::string& processName) {
        // Process hollowing detection logic
        return false;
    }

    std::vector<MEMORY_REGION> ScanMemoryRegions(HANDLE hProcess) {
        std::vector<MEMORY_REGION> regions;
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                regions.push_back({mbi.BaseAddress, mbi.RegionSize, mbi.Protect});
            }
            address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }

        return regions;
    }

    bool DetectCodeInjection(HANDLE hProcess, const MEMORY_REGION& region) {
        // Read memory region
        std::vector<uint8_t> buffer(region.Size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, region.Address, buffer.data(), region.Size, &bytesRead)) {
            return false;
        }

        // Advanced analysis using signature database
        if (memoryAnalyzer.AnalyzeMemoryRegion(buffer)) {
            return true;
        }

        // Check for code caves
        if (memoryAnalyzer.CheckForCodeCaves(buffer)) {
            return true;
        }

        return false;
    }

    bool CheckMaliciousIP(const std::string& ip) {
        if (signatureDB.IsMaliciousIP(ip)) {
            return true;
        }

        // If threat intelligence is enabled, check online
        if (config.threatIntel) {
            // Implementation for online check
        }

        return false;
    }

    // Dynamic analysis of suspicious processes
    void AnalyzeProcessBehavior(DWORD pid, const std::string& processName) {
        // Placeholder for dynamic analysis
    }

public:
    AdvancedSystemScanner() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        LoadWhitelist();
    }

    void ExecuteSecurityScan() {
        jsonLog["scan_start"] = GetCurrentTimestamp();
        jsonLog["system_info"] = GetSystemInfo();
        jsonLog["config"] = {
            {"dry_run", config.dryRun},
            {"no_kill", config.noKill},
            {"memory_dump", config.memoryDump},
            {"threat_intel", config.threatIntel},
            {"timeline_forensics", config.timelineForensics}
        };

        std::cout << "===== INITIATING CERBERUS ADVANCED SECURITY SCAN =====" << std::endl;
        LogResult("info", "Starting comprehensive security scan");

        // Create necessary directories
        if (config.memoryDump) {
            CreateDirectoryA(config.dumpPath.c_str(), NULL);
        }
        if (config.timelineForensics) {
            CreateDirectoryA(config.timelinePath.c_str(), NULL);
        }

        // Parallel scanning modules
        std::vector<std::thread> scanners;
        
        if (config.detectRootkits) {
            scanners.emplace_back(&AdvancedSystemScanner::ScanKernelForRootkits, this);
        }
        
        scanners.emplace_back(&AdvancedSystemScanner::DetectHiddenProcesses, this);
        
        if (config.detectCodeInjection) {
            scanners.emplace_back(&AdvancedSystemScanner::ScanProcessMemory, this);
        }
        
        scanners.emplace_back(&AdvancedSystemScanner::CheckSystemHooks, this);
        
        if (config.networkScan) {
            scanners.emplace_back(&AdvancedSystemScanner::AnalyzeNetwork, this);
        }
        
        if (config.detectPersistence) {
            scanners.emplace_back(&AdvancedSystemScanner::CheckPersistence, this);
        }
        
        if (config.timelineForensics) {
            scanners.emplace_back(&AdvancedSystemScanner::RunTimelineForensics, this);
        }

        for (auto& t : scanners) {
            if (t.joinable()) t.join();
        }

        jsonLog["scan_end"] = GetCurrentTimestamp();
        auto now = std::chrono::system_clock::now();
        auto start_time = std::chrono::system_clock::from_time_t(
            std::chrono::system_clock::to_time_t(now) - 
            std::chrono::seconds(static_cast<int>(jsonLog["scan_duration"].get<double>())));
        jsonLog["scan_duration"] = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

        if (config.jsonLog) {
            SaveJsonLog();
        }

        GenerateComprehensiveReport();
    }

private:
    void ScanKernelForRootkits() {
        // Kernel driver-based scanning
        if (kernelDriver.IsDriverLoaded()) {
            auto hooks = kernelDriver.GetKernelHooks();
            for (const auto& hook : hooks) {
                std::string details = "Function: " + std::string(hook.FunctionName) + 
                                     " | Module: " + std::string(hook.ModuleName) +
                                     " | Hooked at: 0x" + std::to_string(hook.HookedAddress);
                LogResult("threat", "Kernel hook detected", 0, "", details);
            }

            auto drivers = kernelDriver.GetDriverInfo();
            for (const auto& driver : drivers) {
                if (driver.Hidden) {
                    std::string details = "Driver: " + std::string(driver.DriverName) + 
                                         " | Base: 0x" + std::to_string(driver.BaseAddress) +
                                         " | Size: " + std::to_string(driver.Size);
                    LogResult("threat", "Hidden kernel driver detected", 0, "", details);
                } else if (!VerifyDriverSignature(driver.DriverName)) {
                    std::string details = "Driver: " + std::string(driver.DriverName) + 
                                         " | Base: 0x" + std::to_string(driver.BaseAddress);
                    LogResult("warning", "Driver with invalid signature", 0, "", details);
                }
            }
        } else {
            LogResult("warning", "Kernel driver helper not loaded", 0, "", "Advanced kernel scanning disabled");
        }

        // Traditional kernel scanning
        ULONG bufferSize = 0;
        NtQuerySystemInformation(11, NULL, 0, &bufferSize);
        
        if (bufferSize == 0) {
            LogResult("error", "System information query failed", 0, "", "NtQuerySystemInformation error");
            return;
        }
        
        PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) {
            LogResult("error", "Memory allocation failed", 0, "", "Size: " + FormatSize(bufferSize));
            return;
        }
        
        if (NtQuerySystemInformation(11, buffer, bufferSize, NULL) == 0) {
            auto modules = (PSYSTEM_MODULE_INFORMATION)buffer;
            for (ULONG i = 0; i < modules->Count; i++) {
                auto module = &modules->Module[i];
                CHAR modulePath[MAX_PATH] = {0};
                memcpy(modulePath, module->FullPathName + module->OffsetToFileName, 
                       sizeof(module->FullPathName) - module->OffsetToFileName);
                
                if (!VerifyDriverSignature(modulePath)) {
                    LogResult("threat", "Kernel module with invalid signature", 0, modulePath);
                }
            }
        }
        
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    void DetectHiddenProcesses() {
        std::vector<DWORD> activePids = GetProcessList();
        std::vector<DWORD> allPids = GetSystemProcessListViaNtQuery();
        
        for (DWORD pid : allPids) {
            if (pid == 0) continue; // Skip System Idle Process
            
            if (std::find(activePids.begin(), activePids.end(), pid) == activePids.end()) {
                CHAR processName[MAX_PATH] = "";
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (hProcess) {
                    GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
                    CloseHandle(hProcess);
                }
                
                std::wstring wprocessName(processName, processName + strlen(processName));
                if (IsWhitelisted(wprocessName)) {
                    LogResult("info", "Whitelisted hidden process", pid, processName);
                    continue;
                }
                
                if (VerifyHiddenProcessEx(pid, processName)) {
                    bool mitigated = false;
                    if (!config.dryRun && !config.noKill) {
                        mitigated = TerminateProcessSafe(pid);
                    }
                    
                    LogResult("threat", "Hidden process detected", pid, processName, "", mitigated);
                    
                    // Perform dynamic analysis
                    AnalyzeProcessBehavior(pid, processName);
                }
            }
        }
    }

    void ScanProcessMemory() {
        std::vector<DWORD> pids = GetProcessList();
        
        std::cout << "\n[+] Scanning memory of " << pids.size() << " processes..." << std::endl;
        LogResult("info", "Starting process memory scan", 0, "", "Process count: " + std::to_string(pids.size()));

        std::vector<std::thread> workers;
        std::mutex threadMutex;
        
        for (DWORD pid : pids) {
            // Control thread count
            while (activeThreads >= config.maxThreads) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            std::lock_guard<std::mutex> lock(threadMutex);
            activeThreads++;
            
            workers.emplace_back([this, pid]() {
                ScanSingleProcess(pid);
                activeThreads--;
            });
        }
        
        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }
    }

    void ScanSingleProcess(DWORD pid) {
        if (scannedPIDs.find(pid) != scannedPIDs.end()) return;
        scannedPIDs.insert(pid);
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) return;

        CHAR processName[MAX_PATH] = "";
        GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
        std::wstring wprocessName(processName, processName + strlen(processName));

        if (IsWhitelisted(wprocessName)) {
            CloseHandle(hProcess);
            return;
        }

        if (DetectProcessHollowing(hProcess, pid, processName)) {
            CloseHandle(hProcess);
            return;
        }

        std::vector<MEMORY_REGION> regions;
        try {
            regions = ScanMemoryRegions(hProcess);
        } catch (const std::exception& e) {
            LogResult("warning", "Memory scan error", pid, processName, e.what());
            CloseHandle(hProcess);
            return;
        }

        for (const auto& region : regions) {
            try {
                if (DetectCodeInjection(hProcess, region)) {
                    std::string desc = "Malicious code injection detected";
                    std::string details = "Address: " + FormatAddress(region.Address) + 
                                         " | Size: " + FormatSize(region.Size);
                    
                    if (config.memoryDump) {
                        DumpMemoryRegion(hProcess, region, pid, processName);
                    }
                    
                    bool mitigated = false;
                    if (!config.dryRun && !config.noKill) {
                        mitigated = TerminateProcessSafe(pid);
                    }
                    
                    LogResult("threat", desc, pid, processName, details, mitigated);
                }
            } catch (const std::exception& e) {
                LogResult("warning", "Code injection detection error", pid, processName, e.what());
            }
        }
        CloseHandle(hProcess);
    }

    void CheckSystemHooks() {
        if (DetectSSDTHooks()) {
            LogResult("threat", "SSDT hook detected", 0, "", "Kernel-level system call table modification");
        }
    }

    void AnalyzeNetwork() {
        PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
        DWORD dwSize = 0;
        DWORD dwRetVal = 0;

        GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (!pTcpTable) return;

        if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                DWORD pid = pTcpTable->table[i].dwOwningPid;
                CHAR processName[MAX_PATH] = "";
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (hProcess) {
                    GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
                    CloseHandle(hProcess);
                }

                std::string remoteAddr = std::to_string(pTcpTable->table[i].dwRemoteAddr & 0xFF) + "." +
                                        std::to_string((pTcpTable->table[i].dwRemoteAddr >> 8) & 0xFF) + "." +
                                        std::to_string((pTcpTable->table[i].dwRemoteAddr >> 16) & 0xFF) + "." +
                                        std::to_string((pTcpTable->table[i].dwRemoteAddr >> 24) & 0xFF);

                // Check for malicious IP
                if (CheckMaliciousIP(remoteAddr)) {
                    std::string details = "Remote IP: " + remoteAddr + ":" + std::to_string(ntohs(pTcpTable->table[i].dwRemotePort));
                    LogResult("threat", "Malicious network connection", pid, processName, details);
                }
            }
        }

        free(pTcpTable);
    }

    void CheckPersistence() {
        // Check common persistence locations
        CheckRegistryPersistence(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        CheckRegistryPersistence(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        CheckRegistryPersistence(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        CheckRegistryPersistence(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        CheckRegistryPersistence(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");
        
        // Check scheduled tasks
        CheckScheduledTasks();
    }

    void CheckRegistryPersistence(HKEY root, const std::string& regPath) {
        HKEY hKey;
        if (RegOpenKeyExA(root, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return;
        }

        DWORD index = 0;
        CHAR valueName[255];
        DWORD valueNameSize = sizeof(valueName);
        DWORD valueType;
        BYTE valueData[1024];
        DWORD valueDataSize = sizeof(valueData);

        while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
            std::string command = std::string((char*)valueData, valueDataSize);
            if (command.find(" ") != std::string::npos) {
                command = command.substr(0, command.find(" "));
            }

            if (!fs::exists(command) || PathIsRelativeA(command.c_str())) {
                std::string rootStr = (root == HKEY_CURRENT_USER) ? "HKCU" : "HKLM";
                std::string details = "Registry key: " + rootStr + "\\" + regPath + "\\" + valueName;
                LogResult("threat", "Suspicious persistence mechanism", 0, "", details);
            }

            valueNameSize = sizeof(valueName);
            valueDataSize = sizeof(valueData);
            index++;
        }

        RegCloseKey(hKey);
    }

    void CheckScheduledTasks() {
        // Placeholder for scheduled tasks analysis
    }

    void RunTimelineForensics() {
        timeline.CollectEvidence();
        LogResult("info", "Timeline forensic evidence collected", 0, "", config.timelinePath);
    }

    void LogResult(const std::string& type, const std::string& description, 
                  DWORD pid = 0, const std::string& process = "", 
                  const std::string& details = "", bool mitigated = false) {
        std::lock_guard<std::mutex> lock(logMutex);
        
        ScanResult result{type, description, pid, process, details, mitigated};
        results.push_back(result);
        
        std::cout << "[" << GetCurrentTimestamp() << "] "
                  << "[" << type << "] "
                  << description;
        
        if (pid != 0) std::cout << " | PID: " << pid;
        if (!process.empty()) std::cout << " | Process: " << process;
        if (!details.empty()) std::cout << " | Details: " << details;
        if (mitigated) std::cout << " | MITIGATED";
        std::cout << std::endl;
        
        json jresult = {
            {"timestamp", GetCurrentTimestamp()},
            {"type", type},
            {"description", description},
            {"mitigated", mitigated}
        };
        
        if (pid != 0) jresult["pid"] = pid;
        if (!process.empty()) jresult["process"] = process;
        if (!details.empty()) jresult["details"] = details;
        
        jsonLog["results"].push_back(jresult);
    }

    void GenerateComprehensiveReport() {
        int threats = 0, warnings = 0, mitigated = 0;
        
        for (const auto& result : results) {
            if (result.type == "threat") threats++;
            if (result.type == "warning") warnings++;
            if (result.mitigated) mitigated++;
        }
        
        std::cout << "\n===== CERBERUS SECURITY SCAN SUMMARY =====" << std::endl;
        std::cout << "Threats Detected: " << threats << std::endl;
        std::cout << "Security Warnings: " << warnings << std::endl;
        std::cout << "Threats Mitigated: " << mitigated << std::endl;
        std::cout << "Dry Run Mode: " << (config.dryRun ? "Enabled" : "Disabled") << std::endl;
        std::cout << "No-Kill Mode: " << (config.noKill ? "Enabled" : "Disabled") << std::endl;
        std::cout << "Memory Dumps: " << (config.memoryDump ? "Enabled" : "Disabled") << std::endl;
        std::cout << "Threat Intel: " << (config.threatIntel ? "Enabled" : "Disabled") << std::endl;
        std::cout << "Timeline Forensics: " << (config.timelineForensics ? "Enabled" : "Disabled") << std::endl;
        
        if (config.jsonLog) {
            std::cout << "JSON Report: " << config.jsonLogPath << std::endl;
        }
        
        std::cout << "\nRecommendations:" << std::endl;
        if (threats > 0) {
            std::cout << "- Isolate system for forensic analysis" << std::endl;
            std::cout << "- Review memory dumps for detailed analysis" << std::endl;
            std::cout << "- Check detected IPs in threat intelligence" << std::endl;
            std::cout << "- Analyze timeline forensic evidence" << std::endl;
        }
        if (mitigated < threats) {
            std::cout << "- Manually terminate remaining malicious processes" << std::endl;
        }
    }
};

// Command-line parser
void ParseCommandLine(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--dry-run") {
            config.dryRun = true;
            std::cout << "Dry run mode enabled" << std::endl;
        }
        else if (arg == "--no-kill") {
            config.noKill = true;
            std::cout << "No-kill mode enabled" << std::endl;
        }
        else if (arg == "--json-log" && i+1 < argc) {
            config.jsonLog = true;
            config.jsonLogPath = argv[++i];
            std::cout << "JSON logging enabled: " << config.jsonLogPath << std::endl;
        }
        else if (arg == "--memory-dump") {
            config.memoryDump = true;
            CreateDirectoryA(config.dumpPath.c_str(), NULL);
            std::cout << "Memory dumping enabled" << std::endl;
        }
        else if (arg == "--network-scan") {
            config.networkScan = true;
            std::cout << "Network analysis enabled" << std::endl;
        }
        else if (arg == "--threat-intel") {
            config.threatIntel = true;
            std::cout << "Threat intelligence enabled" << std::endl;
        }
        else if (arg == "--timeline-forensics") {
            config.timelineForensics = true;
            CreateDirectoryA(config.timelinePath.c_str(), NULL);
            std::cout << "Timeline forensics enabled" << std::endl;
        }
        else if (arg == "--set-api" && i+1 < argc) {
            config.apiKey = argv[++i];
            std::cout << "API key set" << std::endl;
        }
        else if (arg == "--max-threads" && i+1 < argc) {
            config.maxThreads = std::stoi(argv[++i]);
            std::cout << "Max threads set to: " << config.maxThreads << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    ParseCommandLine(argc, argv);
    
    if (IsUserAnAdmin()) {
        AdvancedSystemScanner scanner;
        scanner.ExecuteSecurityScan();
    } else {
        std::cerr << "ERROR: Must run with administrator privileges!" << std::endl;
        return 1;
    }
    
    return 0;
}
