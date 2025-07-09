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

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;

// إعدادات النظام
struct GlobalConfig {
    bool dryRun = false;
    bool noKill = false;
    bool jsonLog = false;
    std::string jsonLogPath = "cerberus_scan.json";
    std::vector<std::wstring> whitelist = {
        L"System", L"Registry", L"smss.exe", 
        L"csrss.exe", L"wininit.exe", L"services.exe"
    };
} config;

// تعريفات نظام متقدمة
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
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

// هيكل النتائج
struct ScanResult {
    std::string type;
    std::string description;
    DWORD pid = 0;
    std::string process;
    std::string details;
    bool mitigated = false;
};

// ====== نواة النظام ======
class KernelScanner {
private:
    _NtQuerySystemInformation NtQuerySystemInformation;
    std::vector<ScanResult> results;
    json jsonLog;

public:
    KernelScanner() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        LoadWhitelist();
    }

    // === فحص النظام الرئيسي ===
    void FullSystemScan() {
        jsonLog["scan_start"] = GetCurrentTimestamp();
        jsonLog["config"] = {
            {"dry_run", config.dryRun},
            {"no_kill", config.noKill}
        };

        std::cout << "===== بدء الفحص الأمني الشامل =====" << std::endl;
        LogResult("info", "بدء الفحص الأمني الشامل");

        ScanKernelForRootkits();
        DetectHiddenProcesses();
        ScanProcessMemory();

        jsonLog["scan_end"] = GetCurrentTimestamp();
        jsonLog["scan_duration"] = jsonLog["scan_end"].get<std::string>() - jsonLog["scan_start"].get<std::string>();

        if (config.jsonLog) {
            SaveJsonLog();
        }

        GenerateSummaryReport();
    }

private:
    // === فحص عميق للذاكرة ===
    void ScanProcessMemory() {
        std::vector<DWORD> pids = GetProcessList();
        
        std::cout << "\n[+] فحص ذاكرة " << pids.size() << " عملية..." << std::endl;
        LogResult("info", "بدء فحص ذاكرة العمليات", 0, "", "عدد العمليات: " + std::to_string(pids.size()));

        for (DWORD pid : pids) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProcess) continue;

            CHAR processName[MAX_PATH] = "";
            GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
            std::wstring wprocessName(processName, processName + strlen(processName));

            // تخطي العمليات في القائمة البيضاء
            if (IsWhitelisted(wprocessName)) {
                CloseHandle(hProcess);
                continue;
            }

            std::vector<MEMORY_REGION> regions;
            try {
                regions = ScanMemory(hProcess);
            } catch (const std::exception& e) {
                LogResult("warning", "خطأ في فحص الذاكرة", pid, processName, e.what());
                CloseHandle(hProcess);
                continue;
            }

            for (const auto& region : regions) {
                try {
                    if (DetectCodeInjection(hProcess, region)) {
                        std::string desc = "حقن كود خبيث في الذاكرة";
                        std::string details = "العنوان: " + FormatAddress(region.Address) + 
                                             " | الحجم: " + FormatSize(region.Size);
                        
                        bool mitigated = false;
                        if (!config.dryRun && !config.noKill) {
                            mitigated = TerminateProcessSafe(pid);
                        }
                        
                        LogResult("threat", desc, pid, processName, details, mitigated);
                    }
                } catch (const std::exception& e) {
                    LogResult("warning", "خطأ في اكتشاف الحقن", pid, processName, e.what());
                }
            }
            CloseHandle(hProcess);
        }
    }

    std::vector<MEMORY_REGION> ScanMemory(HANDLE hProcess) {
        std::vector<MEMORY_REGION> regions;
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        SIZE_T totalScanned = 0;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_READ)) {
                
                // تجاهل المناطق الكبيرة جداً
                if (mbi.RegionSize <= 500 * 1024 * 1024) { // 500MB حد أقصى
                    regions.push_back({
                        mbi.BaseAddress,
                        mbi.RegionSize,
                        mbi.Protect
                    });
                    totalScanned += mbi.RegionSize;
                } else {
                    LogResult("info", "منطقة ذاكرة كبيرة تم تخطيها", 0, "", 
                              "الحجم: " + FormatSize(mbi.RegionSize));
                }
            }
            address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
        
        LogResult("debug", "فحص ذاكرة مكتمل", 0, "", 
                 "المناطق المفحوصة: " + std::to_string(regions.size()) +
                 " | الحجم الإجمالي: " + FormatSize(totalScanned));
        
        return regions;
    }

    // === اكتشاف الحقن الخبيث ===
    bool DetectCodeInjection(HANDLE hProcess, const MEMORY_REGION& region) {
        const SIZE_T MAX_READ_SIZE = 100 * 1024 * 1024; // 100MB
        SIZE_T readSize = min(region.Size, MAX_READ_SIZE);
        
        std::vector<BYTE> buffer(readSize);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(hProcess, region.Address, buffer.data(), readSize, &bytesRead)) {
            DWORD err = GetLastError();
            std::stringstream ss;
            ss << "فشل قراءة الذاكرة عند: " << FormatAddress(region.Address)
               << " | الخطأ: " << err;
            throw std::runtime_error(ss.str());
        }

        // تحليل أنماط الشفرة الخبيثة المتقدمة
        for (SIZE_T i = 0; i < bytesRead - 8; i++) {
            // كشف شيل كود مترابط
            if (buffer[i] == 0x68 && buffer[i+5] == 0xE8) {  // PUSH + CALL
                DWORD callOffset = *reinterpret_cast<DWORD*>(buffer.data() + i + 6);
                if (callOffset > region.Size) {
                    return true;
                }
            }
            
            // كشف حقن الـ DLL
            if (memcmp(buffer.data() + i, "\x68\x00\x00\x00\x00\xE8", 6) == 0) {  // PUSH 0 + CALL
                return true;
            }
        }
        
        return false;
    }

    // === فحص عميق للنواة ===
    void ScanKernelForRootkits() {
        ULONG bufferSize = 0;
        NtQuerySystemInformation(11, NULL, 0, &bufferSize);
        
        if (bufferSize == 0) {
            LogResult("error", "فشل استعلام معلومات النظام", 0, "", "NtQuerySystemInformation فشل");
            return;
        }
        
        PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) {
            LogResult("error", "فشل تخصيص الذاكرة", 0, "", "الحجم: " + FormatSize(bufferSize));
            return;
        }
        
        if (NtQuerySystemInformation(11, buffer, bufferSize, NULL) == 0) {
            auto modules = (PSYSTEM_MODULE_INFORMATION)buffer;
            for (ULONG i = 0; i < modules->Count; i++) {
                auto module = &modules->Module[i];
                CHAR modulePath[MAX_PATH] = {0};
                memcpy(modulePath, module->FullPathName + module->OffsetToFileName, 
                       sizeof(module->FullPathName) - module->OffsetToFileName);
                
                // التحقق من التوقيع الرقمي
                if (!VerifyDriverSignature(modulePath)) {
                    LogResult("threat", "وحدة نواة غير موقعة", 0, modulePath);
                }
                
                // التحقق من التعديلات في الذاكرة
                if (IsModuleModified(module)) {
                    LogResult("threat", "وحدة نواة معدلة", 0, modulePath);
                }
            }
        }
        
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    // === اكتشاف التهديدات المخفية ===
    void DetectHiddenProcesses() {
        std::vector<DWORD> activePids = GetProcessList();
        std::vector<DWORD> allPids = GetSystemProcessList();
        
        for (DWORD pid : allPids) {
            if (std::find(activePids.begin(), activePids.end(), pid) == activePids.end()) {
                CHAR processName[MAX_PATH] = "";
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProcess) {
                    GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
                    CloseHandle(hProcess);
                }
                
                std::wstring wprocessName(processName, processName + strlen(processName));
                if (IsWhitelisted(wprocessName)) {
                    LogResult("info", "عملية مخفية في القائمة البيضاء", pid, processName);
                    continue;
                }
                
                bool mitigated = false;
                if (!config.dryRun && !config.noKill) {
                    mitigated = TerminateProcessSafe(pid);
                }
                
                LogResult("threat", "عملية مخفية مكتشفة", pid, processName, "", mitigated);
            }
        }
    }

    // === تسجيل النتائج ===
    void LogResult(const std::string& type, const std::string& description, 
                  DWORD pid = 0, const std::string& process = "", 
                  const std::string& details = "", bool mitigated = false) {
        ScanResult result{type, description, pid, process, details, mitigated};
        results.push_back(result);
        
        // تسجيل نصي
        std::cout << "[" << GetCurrentTimestamp() << "] "
                  << "[" << type << "] "
                  << description;
        
        if (pid != 0) {
            std::cout << " | PID: " << pid;
        }
        
        if (!process.empty()) {
            std::cout << " | Process: " << process;
        }
        
        if (!details.empty()) {
            std::cout << " | Details: " << details;
        }
        
        if (mitigated) {
            std::cout << " | MITIGATED";
        }
        
        std::cout << std::endl;
        
        // تسجيل JSON
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

    // === إنهاء آمن للعمليات ===
    bool TerminateProcessSafe(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) return false;
        
        BOOL result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        
        return result;
    }

    // === تحميل القائمة البيضاء ===
    void LoadWhitelist() {
        std::ifstream file("whitelist.txt");
        if (!file.is_open()) return;
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                std::wstring wline(line.begin(), line.end());
                config.whitelist.push_back(wline);
            }
        }
    }

    // === التحقق من القائمة البيضاء ===
    bool IsWhitelisted(const std::wstring& processName) {
        for (const auto& item : config.whitelist) {
            if (_wcsicmp(processName.c_str(), item.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }

    // === وظائف مساعدة ===
    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string FormatAddress(LPVOID address) {
        std::stringstream ss;
        ss << "0x" << std::hex << reinterpret_cast<uintptr_t>(address);
        return ss.str();
    }

    std::string FormatSize(SIZE_T size) {
        const char* units[] = {"B", "KB", "MB", "GB"};
        double value = static_cast<double>(size);
        int unit = 0;
        
        while (value >= 1024 && unit < 3) {
            value /= 1024;
            unit++;
        }
        
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << value << " " << units[unit];
        return ss.str();
    }

    // === وظائف مساعدة ===
    std::vector<DWORD> GetProcessList() {
        std::vector<DWORD> pids;
        DWORD processes[1024], cbNeeded;
        
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD count = cbNeeded / sizeof(DWORD);
            for (DWORD i = 0; i < count; i++) {
                if (processes[i] != 0) pids.push_back(processes[i]);
            }
        }
        return pids;
    }

    std::vector<DWORD> GetSystemProcessList() {
        std::vector<DWORD> pids;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe)) {
                do {
                    pids.push_back(pe.th32ProcessID);
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return pids;
    }

    // === التحقق من التوقيع الرقمي ===
    bool VerifyDriverSignature(LPCSTR driverPath) {
        WINTRUST_FILE_INFO FileData = {0};
        FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileData.pcwszFilePath = LPCWSTR(CA2W(driverPath));
        FileData.hFile = NULL;
        FileData.pgKnownSubject = NULL;

        WINTRUST_DATA WinTrustData = {0};
        WinTrustData.cbStruct = sizeof(WinTrustData);
        WinTrustData.pPolicyCallbackData = NULL;
        WinTrustData.pSIPClientData = NULL;
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        WinTrustData.pFile = &FileData;
        WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        WinTrustData.hWVTStateData = NULL;
        WinTrustData.pwszURLReference = NULL;
        WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
        WinTrustData.dwUIContext = 0;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(NULL, &policyGUID, &WinTrustData);

        // تنظيف حالة التحقق
        WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &WinTrustData);

        return status == ERROR_SUCCESS;
    }

    // === اكتشاف تعديلات النواة ===
    bool IsModuleModified(PSYSTEM_MODULE_ENTRY module) {
        CHAR modulePath[MAX_PATH] = {0};
        memcpy(modulePath, module->FullPathName + module->OffsetToFileName, 
               sizeof(module->FullPathName) - module->OffsetToFileName);
        
        HANDLE hFile = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> fileBuffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        std::vector<BYTE> memBuffer(module->ImageSize);
        SIZE_T bytesReadMem;
        HANDLE hProcess = GetCurrentProcess();
        
        if (!ReadProcessMemory(hProcess, module->ImageBase, memBuffer.data(), 
                              module->ImageSize, &bytesReadMem)) {
            return false;
        }

        bool modified = memcmp(fileBuffer.data(), memBuffer.data(), 
                              min(fileSize, (DWORD)module->ImageSize)) != 0;

        return modified;
    }

    // === حفظ سجل JSON ===
    void SaveJsonLog() {
        std::ofstream o(config.jsonLogPath);
        o << jsonLog.dump(4) << std::endl;
        LogResult("info", "تم حفظ سجل JSON", 0, "", "المسار: " + config.jsonLogPath);
    }

    // === تقرير النتائج ===
    void GenerateSummaryReport() {
        int threats = 0, warnings = 0, mitigated = 0;
        
        for (const auto& result : results) {
            if (result.type == "threat") threats++;
            if (result.type == "warning") warnings++;
            if (result.mitigated) mitigated++;
        }
        
        std::cout << "\n===== ملخص النتائج =====" << std::endl;
        std::cout << "التهديدات المكتشفة: " << threats << std::endl;
        std::cout << "التحذيرات: " << warnings << std::endl;
        std::cout << "التهديدات المعالجة: " << mitigated << std::endl;
        std::cout << "وضع المحاكاة: " << (config.dryRun ? "نعم" : "لا") << std::endl;
        std::cout << "وضع عدم الإنهاء: " << (config.noKill ? "نعم" : "لا") << std::endl;
        
        if (config.jsonLog) {
            std::cout << "سجل JSON: " << config.jsonLogPath << std::endl;
        }
    }
};

// === معالج سطر الأوامر ===
void ParseCommandLine(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--dry-run") {
            config.dryRun = true;
            std::cout << "تم تفعيل وضع المحاكاة" << std::endl;
        }
        else if (arg == "--no-kill") {
            config.noKill = true;
            std::cout << "تم تفعيل وضع عدم الإنهاء" << std::endl;
        }
        else if (arg == "--json-log" && i+1 < argc) {
            config.jsonLog = true;
            config.jsonLogPath = argv[++i];
            std::cout << "تم تفعيل سجل JSON: " << config.jsonLogPath << std::endl;
        }
    }
}

// === النظام الرئيسي ===
int main(int argc, char* argv[]) {
    ParseCommandLine(argc, argv);
    
    if (IsUserAnAdmin()) {
        KernelScanner scanner;
        scanner.FullSystemScan();
    } else {
        std::cerr << "يجب تشغيل البرنامج كمسؤول (Administrator)!" << std::endl;
        return 1;
    }
    
    return 0;
}