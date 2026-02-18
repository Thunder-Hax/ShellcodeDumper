#include "utils.h"
#include <fstream>
#include "minhook-master/include/MinHook.h"
#include <windows.h>
#include <direct.h> // Pour _mkdir
#include <psapi.h>
#include <intrin.h>
#include <string>
#include <mutex>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <cstdarg>



#include <set>
#include <vector>
#include <map>
struct DumpRegion { void* base; size_t size; std::string name; };
std::set<void*> dumpedRegions;
std::vector<DumpRegion> regionBuffer;
std::map<void*, size_t> moduleRanges;
std::map<void*, size_t> moduleRangesAll; // all modules (for ownership checks)
HANDLE hDynamicFile = NULL;
std::string processExeDir;
std::string gBaseFolder;
std::mutex base_mutex;
static bool g_writes_enabled = true;

// forward declaration
void DumpRegionImmediate(const DumpRegion& region);
// forward declare dynamic log
void dynamic_log(const char* fmt, ...);

// forward declarations for functions used by init thread
void StoreModuleRanges();
void ScanExportedFunctionTargets();
void ScanExecutablePagesAndDump();
void DumpAllModulesStatic();

DWORD WINAPI InitThreadProc(LPVOID lpParam);
// additional forward declarations
FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
LPVOID WINAPI MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL WINAPI MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
std::string GetProcessExeDir();
std::string GetBaseFolder();
DWORD WINAPI ScannerThreadProc(LPVOID);
// forward declare module relation helper
bool IsModuleRelatedToProcess(const std::string& path);

// globals
typedef FARPROC (WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
GetProcAddress_t fpGetProcAddress = nullptr;

// Hooks for runtime allocations/protections types and globals
typedef LPVOID (WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
static VirtualAlloc_t fpVirtualAlloc = nullptr;
static VirtualProtect_t fpVirtualProtect = nullptr;

static volatile bool g_run_scanner = true;
static HANDLE g_scanner_thread = NULL;

std::mutex log_mutex;
std::mutex file_mutex;
void log_to_file(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(log_mutex);
    // ensure base folder configured (will prompt if needed)
    if (gBaseFolder.empty()) {
        std::string bf = GetBaseFolder();
        if (bf.empty()) { g_writes_enabled = false; return; }
        // gBaseFolder is set by GetBaseFolder when it returns non-empty
    }
    std::string logPath = gBaseFolder + "\\hooklog.txt";
    _mkdir(gBaseFolder.c_str());
    FILE* f = nullptr;
    if (fopen_s(&f, logPath.c_str(), "a") != 0 || !f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

// Show a folder picker to the user to choose base folder (fallback used elsewhere)
std::string PromptForFolder(const std::string& title, const std::string& initial) {
    BROWSEINFOA bi = {0};
    char path[MAX_PATH] = {0};
    bi.hwndOwner = NULL;
    bi.lpszTitle = title.c_str();
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl) {
        if (SHGetPathFromIDListA(pidl, path)) {
            CoTaskMemFree(pidl);
            return std::string(path);
        }
        CoTaskMemFree(pidl);
    }
    return std::string();
}

// Return the base folder to use for dumps/logs. Will prompt user if not configured via env.
std::string GetBaseFolder() {
    std::lock_guard<std::mutex> lk(base_mutex);
    if (!gBaseFolder.empty()) return gBaseFolder;
    // check environment variable first
    char* env = nullptr; size_t len = 0;
    if (_dupenv_s(&env, &len, "THUNDERMENU_DIR") == 0 && env && len > 0) {
        gBaseFolder = std::string(env);
        free(env);
    } else {
        // prompt the user for a folder (may show UI)
        std::string initial = processExeDir.empty() ? "C:\\" : processExeDir;
        std::string picked = PromptForFolder("Select folder to save dumps and logs", initial);
        if (!picked.empty()) gBaseFolder = picked;
        else {
            // user cancelled: do not set a default folder
            return std::string();
        }
    }
    if (!gBaseFolder.empty() && (gBaseFolder.back() == '\\' || gBaseFolder.back() == '/')) gBaseFolder.pop_back();
    // ensure directory exists
    _mkdir(gBaseFolder.c_str());
    return gBaseFolder;
}

// Write a short textual log line into the dynamic dump file (flushed immediately)
void dynamic_log(const char* fmt, ...) {
    std::lock_guard<std::mutex> lk(file_mutex);
    if (!g_writes_enabled) return;
    DWORD pid = GetCurrentProcessId();
    std::string base = GetBaseFolder();
    if (base.empty()) { g_writes_enabled = false; return; }
    std::string dynamicFolder = base + "\\dynamic";
    _mkdir(dynamicFolder.c_str());
    std::string outFile = dynamicFolder + "\\" + std::to_string(pid) + "_dynamic.dmp";
    if (hDynamicFile == NULL) {
        hDynamicFile = CreateFileA(outFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDynamicFile == INVALID_HANDLE_VALUE) {
            hDynamicFile = NULL;
            return;
        }
    }
    LARGE_INTEGER li; li.QuadPart = 0; SetFilePointerEx(hDynamicFile, li, NULL, FILE_END);
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    if (len > 0) {
        DWORD written = 0;
        WriteFile(hDynamicFile, buf, (DWORD)len, &written, NULL);
        const char nl = '\n';
        WriteFile(hDynamicFile, &nl, 1, &written, NULL);
        FlushFileBuffers(hDynamicFile);
    }
}

DWORD WINAPI InitThreadProc(LPVOID lpParam) {
    // Initialization thread
    AllocConsole();
    FILE* _conout = NULL;
    freopen_s(&_conout, "CONOUT$", "w", stdout);
    // Initialize processExeDir before any logging so GetBaseFolder can prompt with a sensible initial path
    processExeDir = GetProcessExeDir();
    // Force base folder selection now (prompt if not configured via env). If user cancels, disable writes.
    std::string forcedBase = GetBaseFolder();
    if (forcedBase.empty()) {
        // User cancelled or no folder available: disable disk writes and exit init thread
        g_writes_enabled = false;
        printf("[Init] No base folder selected. Disk writes disabled.\n");
        return 0;
    }
    printf("------------------------------ STARTING HOOKING (init thread) -------------------------------\n");
    log_to_file("------------------------------ STARTING HOOKING (init thread) -------------------------------");
    printf("[Init] Process exe dir: %s\n", processExeDir.c_str());
    log_to_file("[Init] Process exe dir: %s", processExeDir.c_str());

    // Store modules and perform scans
    StoreModuleRanges();
    ScanExportedFunctionTargets();
    ScanExecutablePagesAndDump();
    DumpAllModulesStatic();

    // Init MinHook
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        printf("[MinHook] MH_Initialize failed: %d\n", st);
        log_to_file("[MinHook] MH_Initialize failed: %d", st);
        return 0;
    }

    st = MH_CreateHook(&GetProcAddress, &MyGetProcAddress, reinterpret_cast<LPVOID*>(&fpGetProcAddress));
    if (st == MH_OK) {
        st = MH_EnableHook(&GetProcAddress);
        if (st == MH_OK) {
            printf("[MinHook] GetProcAddress hooked\n");
            log_to_file("[MinHook] GetProcAddress hooked");
        } else {
            printf("[MinHook] MH_EnableHook failed: %d\n", st);
            log_to_file("[MinHook] MH_EnableHook failed: %d", st);
        }
    } else {
        printf("[MinHook] MH_CreateHook for GetProcAddress failed: %d\n", st);
        log_to_file("[MinHook] MH_CreateHook for GetProcAddress failed: %d", st);
    }

    // Hook VirtualAlloc and VirtualProtect to catch runtime code allocations/protections
    st = MH_CreateHookApi(L"kernel32", "VirtualAlloc", &MyVirtualAlloc, reinterpret_cast<LPVOID*>(&fpVirtualAlloc));
    if (st == MH_OK) {
        MH_EnableHook(MH_ALL_HOOKS);
        printf("[MinHook] VirtualAlloc hooked\n");
        log_to_file("[MinHook] VirtualAlloc hooked");
    } else {
        printf("[MinHook] MH_CreateHookApi VirtualAlloc failed: %d\n", st);
        log_to_file("[MinHook] MH_CreateHookApi VirtualAlloc failed: %d", st);
    }
    st = MH_CreateHookApi(L"kernel32", "VirtualProtect", &MyVirtualProtect, reinterpret_cast<LPVOID*>(&fpVirtualProtect));
    if (st == MH_OK) {
        MH_EnableHook(MH_ALL_HOOKS);
        printf("[MinHook] VirtualProtect hooked\n");
        log_to_file("[MinHook] VirtualProtect hooked");
    } else {
        printf("[MinHook] MH_CreateHookApi VirtualProtect failed: %d\n", st);
        log_to_file("[MinHook] MH_CreateHookApi VirtualProtect failed: %d", st);
    }

    // No periodic scanner thread: scans already executed once above (avoid infinite loop)

    return 0;
}

// (hooks types and globals declared earlier)

LPVOID WINAPI MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID result = NULL;
    if (fpVirtualAlloc) result = fpVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    else result = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    if (result && (flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        DumpRegion r = { result, dwSize, std::string("virtualalloc") };
        regionBuffer.push_back(r);
        DumpRegionImmediate(r);
    }
    return result;
}

BOOL WINAPI MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    BOOL res = FALSE;
    if (fpVirtualProtect) res = fpVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    else res = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (res && (flNewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        DumpRegion r = { lpAddress, dwSize, std::string("virtualprotect") };
        regionBuffer.push_back(r);
        DumpRegionImmediate(r);
    }
    return res;
}

DWORD WINAPI ScannerThreadProc(LPVOID) {
    while (g_run_scanner) {
        // update module ranges and scan memory periodically
        StoreModuleRanges();
        ScanExportedFunctionTargets();
        ScanExecutablePagesAndDump();
        Sleep(5000);
    }
    return 0;
}

// Scan all committed executable pages in the process and dump pages that are not part of any loaded module
void ScanExecutablePagesAndDump() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* maxAddr = (BYTE*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxAddr) {
        SIZE_T res = VirtualQuery(addr, &mbi, sizeof(mbi));
        if (res == 0) break;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            // Check if this memory belongs to a module
            HMODULE hm = NULL;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)mbi.BaseAddress, &hm)) {
                // It belongs to a module; only consider it if module is related to the injected process
                char modName[MAX_PATH] = {0};
                if (GetModuleFileNameA(hm, modName, sizeof(modName))) {
                    if (IsModuleRelatedToProcess(modName)) {
                        void* regionKey = mbi.BaseAddress;
                        if (dumpedRegions.find(regionKey) == dumpedRegions.end()) {
                            dumpedRegions.insert(regionKey);
                        // create a friendly name: basename + +offset
                        std::string full = modName;
                        size_t p = full.find_last_of("\\/");
                        std::string baseName = (p != std::string::npos) ? full.substr(p + 1) : full;
                        uintptr_t baseModuleAddr = (uintptr_t)mbi.AllocationBase;
                        uintptr_t regionAddr = (uintptr_t)mbi.BaseAddress;
                        uintptr_t off = regionAddr - baseModuleAddr;
                        char friendly[512];
                        _snprintf_s(friendly, sizeof(friendly), "%s+0x%zx", baseName.c_str(), off);
                        std::string name = std::string(friendly);
                        DumpRegion r = {mbi.BaseAddress, mbi.RegionSize, name};
                        regionBuffer.push_back(r);
                        printf("[ScanPages] Found executable module region (related) base=0x%p size=0x%lx module=%s\n", mbi.BaseAddress, (unsigned long)mbi.RegionSize, name.c_str());
                        log_to_file("[ScanPages] Found executable module region (related) base=0x%p size=0x%lx module=%s", mbi.BaseAddress, (unsigned long)mbi.RegionSize, name.c_str());
                            DumpRegionImmediate(r);
                        }
                    } else {
                        // skip pages belonging to unrelated/system modules
                    }
                }
            } else {
                // No module owns this page: likely shellcode/dynamic
                void* regionKey = mbi.BaseAddress;
                if (dumpedRegions.find(regionKey) == dumpedRegions.end()) {
                    dumpedRegions.insert(regionKey);
                    // anonymous region, name by base address and size
                    char an[64];
                    _snprintf_s(an, sizeof(an), "anonyme_0x%p_0x%llx", mbi.BaseAddress, (unsigned long long)mbi.RegionSize);
                    std::string name = std::string(an);
                    DumpRegion r = {mbi.BaseAddress, mbi.RegionSize, name};
                    regionBuffer.push_back(r);
                    printf("[ScanPages] Found executable anonymous region base=0x%p size=0x%lx\n", mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                    log_to_file("[ScanPages] Found executable anonymous region base=0x%p size=0x%lx", mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                    DumpRegionImmediate(r);
                }
            }
        }
        SIZE_T step = mbi.RegionSize ? mbi.RegionSize : 0x1000;
        addr += step;
    }
}

// Dump a detected region immediately to a separate file so we don't rely on DLL unload
void DumpRegionImmediate(const DumpRegion& region) {
    DWORD pid = GetCurrentProcessId();
    if (!g_writes_enabled) return;
    std::string baseFolder = GetBaseFolder();
    if (baseFolder.empty()) { g_writes_enabled = false; return; }
    std::string dynamicFolder = baseFolder + "\\dynamic";
    _mkdir(baseFolder.c_str());
    _mkdir(dynamicFolder.c_str());
    // Append this region into a single dynamic dump file
    std::string outFile = dynamicFolder + "\\" + std::to_string(pid) + "_dynamic.dmp";
    // Open the dynamic dump file once and reuse the handle to avoid costly open/close per region.
    {
        std::lock_guard<std::mutex> lk(file_mutex);
        if (hDynamicFile == NULL) {
            hDynamicFile = CreateFileA(outFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDynamicFile == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                printf("[DynamicDump] Failed to open dynamic dump %s error=%lu\n", outFile.c_str(), err);
                log_to_file("[DynamicDump] Failed to open dynamic dump %s error=%lu", outFile.c_str(), err);
                hDynamicFile = NULL;
                return;
            }
        }
        // seek to end for append
        LARGE_INTEGER li; li.QuadPart = 0; SetFilePointerEx(hDynamicFile, li, NULL, FILE_END);
    }

    // sanitize name for header
    std::string safeName = region.name;
    for (char &c : safeName) if (c == '\\' || c == '/' || c == ':' || c == '"' || c == '<' || c == '>' || c == '|' || c == '?') c = '_';
    char hdr[512];
    int hdrlen = _snprintf_s(hdr, sizeof(hdr), "%s\nbase=0x%p\nsize=%llu\nDATA:\n", safeName.c_str(), region.base, (unsigned long long)region.size);
    DWORD written = 0;
    WriteFile(hDynamicFile, hdr, (DWORD)hdrlen, &written, NULL);
    FlushFileBuffers(hDynamicFile);

    // Read region from our process safely using ReadProcessMemory in chunks
    HANDLE hProc = GetCurrentProcess();
    uintptr_t baseAddr = (uintptr_t)region.base;
    size_t remaining = region.size;
    size_t offset = 0;
    const size_t CHUNK = 0x100000; // 1MB
    std::vector<char> buf(CHUNK);
    while (remaining > 0) {
        size_t toRead = remaining > CHUNK ? CHUNK : remaining;
        SIZE_T actuallyRead = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(baseAddr + offset), buf.data(), toRead, &actuallyRead) || actuallyRead == 0) {
            DWORD err = GetLastError();
            printf("[DynamicDump] ReadProcessMemory failed at 0x%p size=%zu err=%lu\n", (void*)(baseAddr + offset), toRead, err);
            log_to_file("[DynamicDump] ReadProcessMemory failed at 0x%p size=%zu err=%lu", (void*)(baseAddr + offset), toRead, err);
            break;
        }
        DWORD w = 0;
        {
            std::lock_guard<std::mutex> lk(file_mutex);
            if (hDynamicFile) {
                if (!WriteFile(hDynamicFile, buf.data(), (DWORD)actuallyRead, &w, NULL)) {
                    DWORD err = GetLastError();
                    printf("[DynamicDump] WriteFile failed err=%lu\n", err);
                    log_to_file("[DynamicDump] WriteFile failed err=%lu", err);
                    break;
                }
                FlushFileBuffers(hDynamicFile);
            } else {
                break; // file handle not available
            }
        }
        remaining -= actuallyRead;
        offset += actuallyRead;
    }
    const char sep[] = "\n---END_REGION---\n";
    {
        std::lock_guard<std::mutex> lk(file_mutex);
        if (hDynamicFile) {
            WriteFile(hDynamicFile, sep, (DWORD)strlen(sep), &written, NULL);
            // ensure data is flushed to disk so external tools see updates in (near) real-time
            FlushFileBuffers(hDynamicFile);
        }
    }
    printf("[DynamicDump] Appended region %s base=0x%p size=0x%llx\n", safeName.c_str(), region.base, (unsigned long long)region.size);
    log_to_file("[DynamicDump] Appended region %s base=0x%p size=0x%llx", safeName.c_str(), region.base, (unsigned long long)region.size);
}

// Filtre les modules système (dans C:\\Windows)
bool IsSystemModule(const std::string& path) {
    return path.find("C:\\Windows\\") == 0 || path.find("C:/Windows/") == 0;
}

// Retourne le dossier de l'exécutable du process injecté (avec trailing slash)
std::string GetProcessExeDir() {
    char exePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePath, sizeof(exePath)) == 0) return std::string();
    std::string p = exePath;
    size_t pos = p.find_last_of("\\/");
    if (pos == std::string::npos) return std::string();
    return p.substr(0, pos + 1);
}

// Vérifie si un module est lié au process injecté (même dossier) et pas un module système
bool IsModuleRelatedToProcess(const std::string& path) {
    if (path.empty()) return false;
    if (IsSystemModule(path)) return false;
    if (processExeDir.empty()) return true; // si non initialisée, laisser passer
    return path.find(processExeDir) == 0;
}

void DumpAllModulesStatic() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = GetCurrentProcess();
    std::string baseFolder = GetBaseFolder();
    std::string staticFolder = baseFolder + "\\static";
    _mkdir(baseFolder.c_str());
    _mkdir(staticFolder.c_str());
    std::string outFile = staticFolder + "\\" + std::to_string(pid) + "_process.dmp";
    printf("[StaticDump] Starting minidump: %s\n", outFile.c_str());
    log_to_file("[StaticDump] Starting minidump: %s", outFile.c_str());

    // Enumerate modules with dynamic buffer to list all modules
    DWORD required = 0;
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &required, LIST_MODULES_ALL)) {
        if (required == 0) {
            DWORD err = GetLastError();
            printf("[StaticDump] EnumProcessModulesEx failed err=%lu\n", err);
            log_to_file("[StaticDump] EnumProcessModulesEx failed err=%lu", err);
        }
    }
    size_t numMods = required / sizeof(HMODULE);
    if (numMods > 0) {
        std::vector<HMODULE> mods(numMods);
        if (EnumProcessModulesEx(hProcess, mods.data(), (DWORD)(numMods * sizeof(HMODULE)), &required, LIST_MODULES_ALL)) {
            size_t actual = required / sizeof(HMODULE);
            printf("[StaticDump] %zu modules enumerated\n", actual);
            log_to_file("[StaticDump] %zu modules enumerated", actual);
            for (size_t i = 0; i < actual; ++i) {
                char modName[MAX_PATH] = {0};
                if (GetModuleFileNameExA(hProcess, mods[i], modName, sizeof(modName))) {
                    printf("[StaticDump] Module: %s\n", modName);
                    log_to_file("[StaticDump] Module: %s", modName);
                }
            }
        } else {
            DWORD err = GetLastError();
            printf("[StaticDump] EnumProcessModulesEx (fill) failed err=%lu\n", err);
            log_to_file("[StaticDump] EnumProcessModulesEx (fill) failed err=%lu", err);
        }
    }

    HANDLE hFile = CreateFileA(outFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        // Use expanded flags to include handles, unloaded modules, threads, and full memory info
        MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory);
        BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, mdt, NULL, NULL, NULL);
        CloseHandle(hFile);
        if (success) {
            printf("[StaticDump] Minidump created: %s\n", outFile.c_str());
            log_to_file("[StaticDump] Minidump created: %s", outFile.c_str());
        } else {
            printf("[StaticDump] Failed to create minidump\n");
            log_to_file("[StaticDump] Failed to create minidump");
        }
    } else {
        printf("[StaticDump] Failed to open file: %s\n", outFile.c_str());
        log_to_file("[StaticDump] Failed to open file: %s", outFile.c_str());
    }

    // Also write a plain text information file listing modules, exports, memory regions and threads
    // This helps to have readable lists alongside the binary minidump
    try {
        std::string infoFile = staticFolder + "\\" + std::to_string(pid) + "_process_info.txt";
        std::ofstream ofs(infoFile.c_str(), std::ofstream::out | std::ofstream::trunc);
        if (ofs.is_open()) {
            ofs << "Process ID: " << pid << "\n";
            ofs << "Modules:\n";
            // enumerate modules
            DWORD required2 = 0;
            if (EnumProcessModulesEx(hProcess, NULL, 0, &required2, LIST_MODULES_ALL) && required2 > 0) {
                size_t nm = required2 / sizeof(HMODULE);
                std::vector<HMODULE> mods2(nm);
                if (EnumProcessModulesEx(hProcess, mods2.data(), (DWORD)(nm * sizeof(HMODULE)), &required2, LIST_MODULES_ALL)) {
                    size_t am = required2 / sizeof(HMODULE);
                    for (size_t i = 0; i < am; ++i) {
                        MODULEINFO mi = {0};
                        char mname[MAX_PATH] = {0};
                        GetModuleInformation(hProcess, mods2[i], &mi, sizeof(mi));
                        GetModuleFileNameExA(hProcess, mods2[i], mname, sizeof(mname));
                        if (!IsModuleRelatedToProcess(mname)) continue; // only include related modules
                        ofs << "  " << mname << "\n";
                        ofs << "    Base: " << mi.lpBaseOfDll << " Size: " << mi.SizeOfImage << "\n";
                        // list exports
                        BYTE* base = (BYTE*)mods2[i];
                        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                                if (expDir.VirtualAddress != 0) {
                                    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
                                    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
                                    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
                                    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
                                    ofs << "    Exports:\n";
                                    for (DWORD ni = 0; ni < exp->NumberOfNames; ++ni) {
                                        const char* en = (const char*)(base + names[ni]);
                                        WORD oi = ords[ni];
                                        DWORD rva = funcs[oi];
                                        ofs << "      " << en << " (ord=" << (oi + exp->Base) << ") rva=0x" << std::hex << rva << std::dec << "\n";
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ofs << "\nMemory Regions:\n";
            SYSTEM_INFO si2; GetSystemInfo(&si2);
            BYTE* a = (BYTE*)si2.lpMinimumApplicationAddress;
            BYTE* ma = (BYTE*)si2.lpMaximumApplicationAddress;
            MEMORY_BASIC_INFORMATION mbi2;
            while (a < ma) {
                if (VirtualQuery(a, &mbi2, sizeof(mbi2)) == sizeof(mbi2)) {
                    ofs << "  Base=" << mbi2.BaseAddress << " Size=" << mbi2.RegionSize << " State=" << mbi2.State << " Protect=" << mbi2.Protect << " Type=" << mbi2.Type << "\n";
                    a = (BYTE*)mbi2.BaseAddress + mbi2.RegionSize;
                } else break;
            }
            // threads
            ofs << "\nThreads:\n";
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te; te.dwSize = sizeof(te);
                if (Thread32First(hSnap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            ofs << "  ThreadID: " << te.th32ThreadID << "\n";
                        }
                    } while (Thread32Next(hSnap, &te));
                }
                CloseHandle(hSnap);
            }
            ofs.close();
            printf("[StaticDump] Process info written: %s\n", infoFile.c_str());
            log_to_file("[StaticDump] Process info written: %s", infoFile.c_str());
        }
    } catch (...) {
        printf("[StaticDump] Failed to write process info file\n");
        log_to_file("[StaticDump] Failed to write process info file");
    }
}

// Dynamic shellcode dump via GetProcAddress hook

FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC result = NULL;
    if (fpGetProcAddress) result = fpGetProcAddress(hModule, lpProcName);
    else result = GetProcAddress(hModule, lpProcName);
    if (result) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(result, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                void* regionKey = mbi.BaseAddress;
                if (dumpedRegions.find(regionKey) == dumpedRegions.end()) {
                    dumpedRegions.insert(regionKey);
                    DWORD pid = GetCurrentProcessId();
                    char modName[MAX_PATH] = {0};
                    GetModuleFileNameA(hModule, modName, sizeof(modName));
                    std::string fullPath = modName;
                    std::string name = fullPath;
                    size_t pos = name.find_last_of("\\/");
                    if (pos != std::string::npos) name = name.substr(pos + 1);
                    // Check if region is outside any module (likely shellcode)
                    bool isShellcode = true;
                    for (const auto& mod : moduleRanges) {
                        uintptr_t base = (uintptr_t)mod.first;
                        uintptr_t size = mod.second;
                        uintptr_t region = (uintptr_t)mbi.BaseAddress;
                        if (region >= base && region < base + size) {
                            isShellcode = false;
                            break;
                        }
                    }
                    if (isShellcode) {
                        DumpRegion r = {mbi.BaseAddress, mbi.RegionSize, name};
                        regionBuffer.push_back(r);
                        // Log detection immediately to console and file so dynamic activity is visible
                        printf("[DynamicDump] Detected region %s (base=0x%p, size=0x%lx)\n", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        log_to_file("[DynamicDump] Detected region %s (base=0x%p, size=0x%lx)", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        // Also append a short textual line into the dynamic dump file for immediate visibility
                        dynamic_log("[DynamicDump] DETECT %s base=0x%p size=0x%lx", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        // Also dump immediately to ensure we capture even if DLL is not unloaded
                        DumpRegionImmediate(r);
                    }
                }
            }
        }
    }
    return result;
}
void StoreModuleRanges() {
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;
    // Use EnumProcessModulesEx to ensure we enumerate all modules (including 32/64-bit differences)
    // enumerate with dynamic buffer
    DWORD required = 0;
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &required, LIST_MODULES_ALL)) {
        if (required == 0) {
            DWORD err = GetLastError();
            printf("[StoreModuleRanges] EnumProcessModulesEx failed err=%lu\n", err);
            log_to_file("[StoreModuleRanges] EnumProcessModulesEx failed err=%lu", err);
            return;
        }
    }
    size_t numMods = required / sizeof(HMODULE);
    std::vector<HMODULE> mods(numMods);
    if (!EnumProcessModulesEx(hProcess, mods.data(), (DWORD)(numMods * sizeof(HMODULE)), &required, LIST_MODULES_ALL)) {
        DWORD err = GetLastError();
        printf("[StoreModuleRanges] EnumProcessModulesEx second call failed err=%lu\n", err);
        log_to_file("[StoreModuleRanges] EnumProcessModulesEx second call failed err=%lu", err);
        return;
    }
    printf("[StoreModuleRanges] %zu modules found\n", numMods);
    log_to_file("[StoreModuleRanges] %zu modules found", numMods);
    for (size_t i = 0; i < numMods; ++i) {
        MODULEINFO modInfo = { 0 };
        char modName[MAX_PATH] = {0};
        if (GetModuleInformation(hProcess, mods[i], &modInfo, sizeof(modInfo))) {
            if (GetModuleFileNameExA(hProcess, mods[i], modName, sizeof(modName))) {
                // Only store modules that are related to the injected process (not system modules)
                if (!IsModuleRelatedToProcess(modName)) continue;
                moduleRanges[(void*)modInfo.lpBaseOfDll] = modInfo.SizeOfImage;
                printf("[StoreModuleRanges] Module: %s (base=0x%p, size=0x%lx)\n", modName, modInfo.lpBaseOfDll, (unsigned long)modInfo.SizeOfImage);
                log_to_file("[StoreModuleRanges] Module: %s (base=0x%p, size=0x%lx)", modName, modInfo.lpBaseOfDll, (unsigned long)modInfo.SizeOfImage);
            }
        }
    }
}

// Scan exported functions of loaded modules and record targets that live outside known module ranges
void ScanExportedFunctionTargets() {
    // Enumerate modules and list ALL exported functions with their offsets and dump their target regions
    HANDLE hProcess = GetCurrentProcess();
    DWORD required = 0;
    if (!EnumProcessModulesEx(hProcess, NULL, 0, &required, LIST_MODULES_ALL) && required == 0) {
        DWORD err = GetLastError();
        printf("[ScanExports] EnumProcessModulesEx failed err=%lu\n", err);
        log_to_file("[ScanExports] EnumProcessModulesEx failed err=%lu", err);
        return;
    }
    size_t numMods = required / sizeof(HMODULE);
    std::vector<HMODULE> mods(numMods);
    if (!EnumProcessModulesEx(hProcess, mods.data(), (DWORD)(numMods * sizeof(HMODULE)), &required, LIST_MODULES_ALL)) {
        DWORD err = GetLastError();
        printf("[ScanExports] EnumProcessModulesEx fill failed err=%lu\n", err);
        log_to_file("[ScanExports] EnumProcessModulesEx fill failed err=%lu", err);
        return;
    }
    size_t actual = required / sizeof(HMODULE);
    for (size_t mi = 0; mi < actual; ++mi) {
        BYTE* base = (BYTE*)mods[mi];
        char modName[MAX_PATH] = {0};
        GetModuleFileNameExA(hProcess, mods[mi], modName, sizeof(modName));
        // Skip modules not related to injected process
        if (!IsModuleRelatedToProcess(modName)) continue;
        printf("[ScanExports] Module: %s base=0x%p\n", modName, base);
        log_to_file("[ScanExports] Module: %s base=0x%p", modName, base);

        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0) continue;
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
        DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);
        DWORD* names = (DWORD*)(base + exp->AddressOfNames);
        WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);

        // Track which ordinals have names
        std::vector<char> hasName(exp->NumberOfFunctions ? exp->NumberOfFunctions : 1);

        // First, named exports
        for (DWORD ni = 0; ni < exp->NumberOfNames; ++ni) {
            const char* exportName = (const char*)(base + names[ni]);
            WORD ordinalIndex = ordinals[ni];
            hasName[ordinalIndex] = 1;
            DWORD funcRva = functions[ordinalIndex];
            void* funcAddr = funcRva ? (void*)(base + funcRva) : nullptr;
            uintptr_t offset = funcAddr ? ((uintptr_t)funcAddr - (uintptr_t)base) : 0;
            printf("[ScanExports] %s!%s ordinal=%u rva=0x%08x addr=0x%p offset=0x%zx\n", modName, exportName, (unsigned int)(ordinalIndex + exp->Base), funcRva, funcAddr, offset);
            log_to_file("[ScanExports] %s!%s ordinal=%u rva=0x%08x addr=0x%p offset=0x%zx", modName, exportName, (unsigned int)(ordinalIndex + exp->Base), funcRva, funcAddr, offset);
            if (funcAddr) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(funcAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                        void* regionKey = mbi.BaseAddress;
                        if (dumpedRegions.find(regionKey) == dumpedRegions.end()) {
                            dumpedRegions.insert(regionKey);
                            std::string name = std::string(modName) + "!" + exportName;
                            regionBuffer.push_back({mbi.BaseAddress, mbi.RegionSize, name});
                            printf("[ScanExports] Dumping region for %s (region=0x%p size=0x%lx)\n", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                            log_to_file("[ScanExports] Dumping region for %s (region=0x%p size=0x%lx)", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                            DumpRegionImmediate({mbi.BaseAddress, mbi.RegionSize, name});
                        }
                    }
                }
            }
        }

        // Then, exports by ordinal only
        for (DWORD oi = 0; oi < exp->NumberOfFunctions; ++oi) {
            if (oi < (DWORD)hasName.size() && hasName[oi]) continue; // already handled
            DWORD funcRva = functions[oi];
            if (funcRva == 0) continue;
            void* funcAddr = (void*)(base + funcRva);
            uintptr_t offset = (uintptr_t)funcAddr - (uintptr_t)base;
            unsigned int displayOrd = oi + exp->Base;
            char ordName[64];
            _snprintf_s(ordName, sizeof(ordName), "<ordinal_%u>", displayOrd);
            printf("[ScanExports] %s!%s ordinal=%u rva=0x%08x addr=0x%p offset=0x%zx\n", modName, ordName, displayOrd, funcRva, funcAddr, offset);
            log_to_file("[ScanExports] %s!%s ordinal=%u rva=0x%08x addr=0x%p offset=0x%zx", modName, ordName, displayOrd, funcRva, funcAddr, offset);
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(funcAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    void* regionKey = mbi.BaseAddress;
                    if (dumpedRegions.find(regionKey) == dumpedRegions.end()) {
                        dumpedRegions.insert(regionKey);
                        std::string name = std::string(modName) + "!" + ordName;
                        regionBuffer.push_back({mbi.BaseAddress, mbi.RegionSize, name});
                        printf("[ScanExports] Dumping region for %s (region=0x%p size=0x%lx)\n", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        log_to_file("[ScanExports] Dumping region for %s (region=0x%p size=0x%lx)", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        DumpRegionImmediate({mbi.BaseAddress, mbi.RegionSize, name});
                    }
                }
            }
        }
    }
}
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        // Initialize process exe dir early so system modules are not treated as "related"
        processExeDir = GetProcessExeDir();
        // Start initialization on a separate thread to avoid doing heavy work inside DllMain
        g_scanner_thread = CreateThread(NULL, 0, InitThreadProc, NULL, 0, NULL);
        break;
    }
    case DLL_PROCESS_DETACH: {
        // Stop scanner thread and hooks, then write remaining buffers
        g_run_scanner = false;
        if (g_scanner_thread) {
            WaitForSingleObject(g_scanner_thread, 5000);
            CloseHandle(g_scanner_thread);
            g_scanner_thread = NULL;
        }

        // Disable hooks and uninitialize MinHook
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();

        // Close dynamic file handle if open
        if (hDynamicFile && hDynamicFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hDynamicFile);
            hDynamicFile = NULL;
        }
        regionBuffer.clear();
        break;
    }
    }
    return TRUE;
}

// Provide a minimal `main` so the project can be linked as an executable
// (some build configurations expect an `main` symbol). This is harmless
// when building as a DLL and ensures the linker error LNK2001 (unresolved
// external symbol main) is avoided.
int main() {
    return 0;
}
