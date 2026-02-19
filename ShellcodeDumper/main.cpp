#include "utils.h"
#include <fstream>
#include "minhook-master/include/MinHook.h"
#include <windows.h>
#include <direct.h> // Pour _mkdir
#include <psapi.h>
#include <intrin.h>
#include <string>
#include <atomic>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <cstdarg>
#include <cctype>
#include <cstring>



#include <set>
#include <vector>
#include <map>
struct DumpRegion { void* base; size_t size; std::string name; };
std::set<void*> dumpedRegions;
std::vector<DumpRegion> regionBuffer;
std::map<void*, size_t> moduleRanges;
// map base -> full path for all enumerated modules
std::map<void*, std::string> modulePaths;
std::map<void*, size_t> moduleRangesAll; // all modules (for ownership checks)
// dynamic file handle removed: dynamic dumps will be produced as full minidumps by the worker
std::string processExeDir;
std::string gBaseFolder;
CRITICAL_SECTION g_base_cs;
static bool g_writes_enabled = true;
// user choice: 0 = small, 1 = full, -1 = not chosen
static int g_dump_choice = -1;

// forward declaration
void DumpRegionImmediate(const DumpRegion& region);
// queue node for background dump worker
struct QNode { DumpRegion region; QNode* next; };
static QNode* g_queue_head = nullptr;
static QNode* g_queue_tail = nullptr;
static CRITICAL_SECTION g_queue_cs;
static std::atomic<bool> g_worker_running(false);
static HANDLE g_worker_thread = NULL;
static HANDLE g_worker_event = NULL;
// Scheduler for periodic related dynamic dumps
static HANDLE g_dynamic_scheduler_thread = NULL;
static std::atomic<bool> g_dynamic_scheduler_running(false);
// Prevent overlapping scheduled dynamic dumps
static std::atomic<bool> g_dynamic_dump_in_progress(false);
// Event signaled by worker when a special related dynamic dump request completes
static HANDLE g_dynamic_done_event = NULL;
// simple atomic counter for dynamic dumps
static std::atomic<unsigned int> g_dynamic_dump_counter(1);
// flag: full dynamic dump written
static std::atomic<bool> g_dynamic_fulldump_written(false);
// user option: include system modules in related scans
static bool g_include_system_modules = false;
// friendly name helper for anonymous regions
std::string GetRegionFriendlyName(void* base, size_t size);
// forward declare dynamic log
void dynamic_log(const char* fmt, ...);

// Try to find a friendly name for an anonymous executable region (best-effort):
// 1) read a short ASCII string at the region start
// 2) try DbgHelp Symbol lookup (if available)
// 3) fallback to an hex signature
std::string GetRegionFriendlyName(void* base, size_t size) {
    // try ascii hint
    const size_t READSZ = 128;
    char buf[READSZ+1] = {0};
    SIZE_T toRead = (size > READSZ) ? READSZ : size;
    SIZE_T actuallyRead = 0;
    if (toRead > 0 && ReadProcessMemory(GetCurrentProcess(), base, buf, toRead, &actuallyRead) && actuallyRead > 0) {
        std::string run;
        for (SIZE_T i = 0; i < actuallyRead; ++i) {
            unsigned char c = (unsigned char)buf[i];
            if (isprint(c) && c != '\r' && c != '\n' && c != '\t') {
                run.push_back((char)c);
                if (run.size() >= 32) break;
            } else {
                if (run.size() >= 4) break;
                run.clear();
            }
    // If the base folder was provided via environment variable, also allow
    // configuring the "include system modules" option via a separate env var
    // so users who skip the UI can still control that behavior.
    if (!gBaseFolder.empty()) {
        char* env2 = nullptr; size_t len2 = 0;
        if (_dupenv_s(&env2, &len2, "THUNDERMENU_INCLUDE_SYSTEM") == 0 && env2) {
            g_include_system_modules = (strcmp(env2, "1") == 0);
            free(env2);
        } else {
            // default to false when not specified
            g_include_system_modules = false;
        }
    }
        }
        if (run.size() >= 4) {
            for (char &c : run) if (c == '\\' || c == '/' || c == ':' || c == '"' || c == '<' || c == '>' || c == '|' || c == '?') c = '_';
            return run;
        }
    }

    // try symbol lookup
    static bool symInit = false;
    if (!symInit) {
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        symInit = true;
    }
    DWORD64 addr = (DWORD64)base;
    BYTE symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    PSYMBOL_INFO pSym = (PSYMBOL_INFO)symBuffer;
    pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSym->MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacement = 0;
    if (SymFromAddr(GetCurrentProcess(), addr, &displacement, pSym)) {
        std::string s(pSym->Name);
        for (char &c : s) if (c == '\\' || c == '/' || c == ':' || c == '"' || c == '<' || c == '>' || c == '|' || c == '?') c = '_';
        return s;
    }

    // fallback: short hex signature
    unsigned char sigbuf[16] = {0}; SIZE_T sr = 0;
    SIZE_T siglen = (size > sizeof(sigbuf)) ? sizeof(sigbuf) : size;
    if (siglen > 0) ReadProcessMemory(GetCurrentProcess(), base, sigbuf, siglen, &sr);
    char sigs[64] = {0}; char* p = sigs; size_t rem = sizeof(sigs);
    for (SIZE_T i = 0; i < sr && i < 8; ++i) {
        int written = sprintf_s(p, rem, "%02X", sigbuf[i]);
        if (written <= 0) break;
        p += written; rem -= written;
    }
    char an[128];
    if (sigs[0] == '\0') _snprintf_s(an, sizeof(an), "anonymous_0x%p_size_0x%llx", base, (unsigned long long)size);
    else _snprintf_s(an, sizeof(an), "anonymous_0x%p_size_0x%llx_sig_%s", base, (unsigned long long)size, sigs);
    return std::string(an);
}

// forward declarations for functions used by init thread
void StoreModuleRanges();
void ScanExportedFunctionTargets();
void ScanExecutablePagesAndDump();
void DumpAllModulesStatic();
void log_to_file(const char* fmt, ...);
BOOL CALLBACK MiniDumpFilterCallback(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
void DumpRelatedModulesDynamic();
// forward declaration: write dynamic process info immediately
void WriteDynamicProcessInfoImmediate();
// Thread procedures
static DWORD WINAPI WorkerThreadProc(LPVOID lpParam);
static DWORD WINAPI SchedulerThreadProc(LPVOID lpParam);
// Helper: return filename component only (no path)
static std::string BaseName(const std::string &p) {
    size_t pos = p.find_last_of("\\/");
    if (pos == std::string::npos) return p;
    return p.substr(pos + 1);
}
// Ensure only the configured base folder and the two allowed subfolders are created
static void EnsureBaseAndSubfolders(const std::string &base) {
    if (base.empty()) return;
    // create base and only these two subfolders: static and dynamic
    _mkdir(base.c_str());
    std::string staticFolder = base + "\\static";
    std::string dynamicFolder = base + "\\dynamic";
    _mkdir(staticFolder.c_str());
    _mkdir(dynamicFolder.c_str());
}
// forward declare base folder helper used by immediate info writer
std::string GetBaseFolder();
// forward declaration: quick test to verify we can create files in the target directory
static bool TestWriteAccess(const std::string &dir);
// Worker thread implementation (moved out of InitThreadProc to avoid lambdas)
static DWORD WINAPI WorkerThreadProc(LPVOID lpParam) {
    while (g_worker_running.load()) {
        DWORD wait = WaitForSingleObject(g_worker_event, INFINITE);
        if (!g_worker_running.load()) break;
        // pop a single node and process sequentially to ensure ordered dumps
        QNode* node = nullptr;
        EnterCriticalSection(&g_queue_cs);
        if (g_queue_head) {
            node = g_queue_head;
            g_queue_head = g_queue_head->next;
            if (g_queue_head == nullptr) g_queue_tail = nullptr;
        }
        LeaveCriticalSection(&g_queue_cs);
        if (!node) continue;
        DumpRegion dr = node->region;
        // Handle special related-dump request enqueued by init/scheduler
        if (dr.name == "__RELATED_DUMP__") {
            // reset done event and perform related dump
            if (g_dynamic_done_event) ResetEvent(g_dynamic_done_event);
            // create the dynamic minidump first
            DumpRelatedModulesDynamic();
            // then write the textual process info so it always appears after the .dmp
            WriteDynamicProcessInfoImmediate();
            // mark as completed in case scheduler awaited this flag
            g_dynamic_dump_in_progress.store(false);
            if (g_dynamic_done_event) SetEvent(g_dynamic_done_event);
            delete node;
            continue;
        }
        bool ok = false;
        MEMORY_BASIC_INFORMATION mbi;
        if (dr.base && VirtualQuery(dr.base, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                BYTE probe = 0; SIZE_T rr = 0;
                if (ReadProcessMemory(GetCurrentProcess(), dr.base, &probe, 1, &rr) && rr == 1) ok = true;
            }
        }
        if (ok) {
            DWORD pid = GetCurrentProcessId();
            std::string base = GetBaseFolder();
            if (!base.empty()) {
                // Ensure base and only allowed subfolders exist (static, dynamic)
                std::string dynamicFolder = base + "\\dynamic";
                EnsureBaseAndSubfolders(base);
                char fname[512];
                std::string safeName = dr.name;
                for (char &c : safeName) if (c == '\\' || c == '/' || c == ':' || c == '"' || c == '<' || c == '>' || c == '|' || c == '?') c = '_';
                unsigned int idx = g_dynamic_dump_counter.fetch_add(1);
                _snprintf_s(fname, sizeof(fname), "%s\\%u_dynamic_%u_0x%p.dmp", dynamicFolder.c_str(), pid, idx, dr.base);
                // directory ensured by EnsureBaseAndSubfolders
                // log attempted path for diagnostics (non-console dynamic prefix removed)
                log_to_file("Attempting to create dynamic minidump: %s", fname);
                HANDLE hFile = CreateFileA(fname, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile == INVALID_HANDLE_VALUE) {
                    // fallback: try to create an empty file with ofstream (ensures file visible) and reopen
                    std::ofstream ofsFail(fname, std::ofstream::out | std::ofstream::binary);
                    if (ofsFail.is_open()) {
                        ofsFail.close();
                        log_to_file("[DynamicDump] Fallback: created empty file: %s", fname);
                        // reopen existing file for writing
                        hFile = CreateFileA(fname, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    }
                }
                if (hFile != INVALID_HANDLE_VALUE) {
                    // choose same minidump flags as static unless user chose small
                    MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory);
                    if (g_dump_choice == 0) mdt = MiniDumpNormal;
                    BOOL okd = MiniDumpWriteDump(GetCurrentProcess(), pid, hFile, mdt, NULL, NULL, NULL);
                    DWORD mdErr = 0;
                    if (!okd) mdErr = GetLastError();
                    CloseHandle(hFile);
                    if (okd) {
                        // print concise console message (no bracket tag) and full path to hooklog
                        std::string outName = BaseName(fname);
                        dynamic_log("Minidump created: %s", outName.c_str());
                        log_to_file("[DynamicDump] Minidump created: %s", fname);
                        // do not create an index file as requested
                    } else {
                        dynamic_log("Minidump failed: %s err=%lu", fname, mdErr);
                        log_to_file("[DynamicDump] Minidump failed: %s err=%lu", fname, mdErr);
                    }
                } else {
                    DWORD err = GetLastError();
                    printf("[DynamicDump] Failed to create minidump file: %s err=%lu\n", fname, err); fflush(stdout);
                    dynamic_log("[DynamicDump] Failed to create minidump file: %s err=%lu", fname, err);
                    log_to_file("[DynamicDump] Failed to create minidump file: %s err=%lu", fname, err);
                }
            }
        }
        delete node;
    }
    return 0;
}

// Scheduler thread implementation
static DWORD WINAPI SchedulerThreadProc(LPVOID /*lpParam*/) {
    const DWORD intervalMs = 1 * 1000; // 1 second (user request)
    while (g_dynamic_scheduler_running.load()) {
        Sleep(intervalMs);
        if (!g_dynamic_scheduler_running.load()) break;
        // Avoid overlapping runs
        bool expected = false;
        if (!g_dynamic_dump_in_progress.compare_exchange_strong(expected, true)) continue;
        if (g_writes_enabled) {
            // Enqueue a special related-dump request first so the worker creates
            // the dynamic minidump before we write the textual process info.
            DumpRegion special = { nullptr, 0, std::string("__RELATED_DUMP__") };
            QNode* n = new QNode(); n->region = special; n->next = nullptr;
            EnterCriticalSection(&g_queue_cs);
            if (g_queue_tail) { g_queue_tail->next = n; g_queue_tail = n; }
            else { g_queue_head = g_queue_tail = n; }
            LeaveCriticalSection(&g_queue_cs);
            if (g_worker_event) SetEvent(g_worker_event);
            // wait for worker to complete the related dump (use event with timeout)
            if (g_dynamic_done_event) {
                // wait up to 5s
                WaitForSingleObject(g_dynamic_done_event, 5000);
            } else {
                // fallback busy-wait
                DWORD waited = 0;
                while (g_dynamic_dump_in_progress.load() && waited < 5000) { Sleep(50); waited += 50; }
            }
            // additionally wait for the expected related dump file to exist (worker writes the textual info)
            {
                std::string relatedPath = GetBaseFolder();
                if (!relatedPath.empty()) {
                    relatedPath += "\\dynamic\\" + std::to_string(GetCurrentProcessId()) + "_dynamic_related.dmp";
                    DWORD tries = 0;
                    while (tries < 100) { // up to ~5s
                        DWORD attr = GetFileAttributesA(relatedPath.c_str());
                        if (attr != INVALID_FILE_ATTRIBUTES) break;
                        Sleep(50); ++tries;
                    }
                }
            }
            // NOTE: Do NOT write process info here — the background worker will write
            // the textual dynamic process info immediately after creating the related
            // dynamic .dmp to guarantee correct ordering and avoid duplicate writes.
        } else {
            // not enabled: clear flag
            g_dynamic_dump_in_progress.store(false);
        }
    }
    return 0;
}
// Helper: return filename component only (no path)

// Quick test to verify we can create files in the target directory. Returns
// true if a small temp file can be created and removed.
static bool TestWriteAccess(const std::string &dir) {
    std::string testPath = dir + "\\__write_test.tmp";
    // ensure directory exists
    CreateDirectoryA(dir.c_str(), NULL);
    HANDLE h = CreateFileA(testPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_to_file("[Diag] TestWriteAccess failed to create %s err=%lu", testPath.c_str(), err);
        dynamic_log("[Diag] TestWriteAccess failed to create %s err=%lu", testPath.c_str(), err);
        return false;
    }
    const char* txt = "ok";
    DWORD written = 0;
    WriteFile(h, txt, (DWORD)strlen(txt), &written, NULL);
    CloseHandle(h);
    // try to remove
    DeleteFileA(testPath.c_str());
    return true;
}
// Write the dynamic process info file immediately (modules, exports, memory regions, threads)
void WriteDynamicProcessInfoImmediate() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = GetCurrentProcess();
    std::string base = GetBaseFolder();
    if (base.empty()) return;
    std::string dynamicFolder = base + "\\dynamic";
    EnsureBaseAndSubfolders(base);
    std::string infoFile = dynamicFolder + "\\" + std::to_string(pid) + "_dynamic_process_info.txt";
    // Wait briefly for the related dynamic .dmp to appear so the textual info
    // does not come before the binary dump. This handles races where the
    // worker is still writing the .dmp.
    std::string relatedDump = dynamicFolder + "\\" + std::to_string(pid) + "_dynamic_related.dmp";
    for (int i = 0; i < 100; ++i) { // ~5s max
        DWORD attr = GetFileAttributesA(relatedDump.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) break;
        Sleep(50);
    }
    try {
        std::ofstream ofs(infoFile.c_str(), std::ofstream::out | std::ofstream::trunc);
        if (!ofs.is_open()) return;
        ofs << "Process ID: " << pid << "\n";
        ofs << "Modules:\n";
        DWORD required2 = 0;
        if (EnumProcessModulesEx(hProcess, NULL, 0, &required2, LIST_MODULES_ALL) && required2 > 0) {
            size_t nm = required2 / sizeof(HMODULE);
            std::vector<HMODULE> mods2(nm);
            if (EnumProcessModulesEx(hProcess, mods2.data(), (DWORD)(nm * sizeof(HMODULE)), &required2, LIST_MODULES_ALL)) {
                size_t am = required2 / sizeof(HMODULE);
                for (size_t i = 0; i < am; ++i) {
                    MODULEINFO mi = {0}; char mname[MAX_PATH] = {0};
                    GetModuleInformation(hProcess, mods2[i], &mi, sizeof(mi));
                    GetModuleFileNameExA(hProcess, mods2[i], mname, sizeof(mname));
                    ofs << "  " << mname << "\n";
                    ofs << "    Base: " << mi.lpBaseOfDll << " Size: " << mi.SizeOfImage << "\n";
                    // Also write module info into the dynamic process info only (no separate dynamic_info log)
                    BYTE* baseAddr = (BYTE*)mods2[i];
                    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)baseAddr;
                    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(baseAddr + dos->e_lfanew);
                        if (nt->Signature == IMAGE_NT_SIGNATURE) {
                            IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                            if (expDir.VirtualAddress != 0) {
                                IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + expDir.VirtualAddress);
                                DWORD* funcs = (DWORD*)(baseAddr + exp->AddressOfFunctions);
                                DWORD* names = (DWORD*)(baseAddr + exp->AddressOfNames);
                                WORD* ords = (WORD*)(baseAddr + exp->AddressOfNameOrdinals);
                                    ofs << "    Exports:\n";
                                for (DWORD ni = 0; ni < exp->NumberOfNames; ++ni) {
                                    const char* en = (const char*)(baseAddr + names[ni]);
                                    WORD oi = ords[ni]; DWORD rva = funcs[oi];
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
        BYTE* a = (BYTE*)si2.lpMinimumApplicationAddress; BYTE* ma = (BYTE*)si2.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi2;
        while (a < ma) {
            if (VirtualQuery(a, &mbi2, sizeof(mbi2)) == sizeof(mbi2)) {
                ofs << "  Base=" << mbi2.BaseAddress << " Size=" << mbi2.RegionSize << " State=" << mbi2.State << " Protect=" << mbi2.Protect << " Type=" << mbi2.Type << "\n";
                a = (BYTE*)mbi2.BaseAddress + mbi2.RegionSize;
            } else break;
        }
        ofs << "\nThreads:\n";
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te; te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do { if (te.th32OwnerProcessID == pid) ofs << "  ThreadID: " << te.th32ThreadID << "\n"; } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
        ofs.close();
        // Log full path only to hooklog (do not print to console) so the
        // dynamic minidump message remains visible first.
        log_to_file("[DynamicInfo] Process info written (immediate): %s", infoFile.c_str());
    } catch(...) { log_to_file("[DynamicInfo] Failed to write immediate process info file"); }
}

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

void log_to_file(const char* fmt, ...) {
    // Non-blocking simple append without mutex. Might interleave across threads,
    // but avoids blocking in hot paths as requested.
    if (!g_writes_enabled) {
        // Even when disk writes are disabled, always echo critical hook startup
        // messages to the console so the user sees that hooks were installed.
        if (fmt && strncmp(fmt, "[MinHook]", 9) == 0) {
            va_list args_console;
            va_start(args_console, fmt);
            vfprintf(stdout, fmt, args_console);
            va_end(args_console);
            printf("\n"); fflush(stdout);
        }
        return;
    }
    // ensure base folder configured (will prompt if needed)
    if (gBaseFolder.empty()) {
        // protect gBaseFolder with CRITICAL_SECTION
        EnterCriticalSection(&g_base_cs);
        std::string bf = GetBaseFolder();
        LeaveCriticalSection(&g_base_cs);
        if (bf.empty()) { g_writes_enabled = false; return; }
    }

    bool isDynamicInfo = (fmt && strncmp(fmt, "[DynamicInfo]", 13) == 0);
    if (isDynamicInfo) {
        // DynamicInfo messages are only written into the dynamic_process_info
        // file by the dedicated writer; do not emit them elsewhere.
        return;
    }

    va_list args;
    va_start(args, fmt);
    std::string logPath = gBaseFolder + "\\hooklog.txt";
    _mkdir(gBaseFolder.c_str());
    FILE* f = nullptr;
    if (fopen_s(&f, logPath.c_str(), "a") == 0 && f) {
        va_list args_file;
        va_copy(args_file, args);
        vfprintf(f, fmt, args_file);
        va_end(args_file);
        fprintf(f, "\n");
        fflush(f);
        fclose(f);
    }
    // Print to console for non-dynamic info messages so static dumps remain unchanged.
    va_list args_console;
    va_copy(args_console, args);
    vfprintf(stdout, fmt, args_console);
    va_end(args_console);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

// Custom folder picker dialog with a checkbox to include system modules.
static const int IDC_EDIT_PATH = 3001;
static const int IDC_BUTTON_BROWSE = 3002;
static const int IDC_CHECK_INCLUDE = 3003;

static LRESULT CALLBACK CustomFolderWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BUTTON_BROWSE) {
            BROWSEINFOA bi = {0};
            char buf[MAX_PATH] = {0};
            bi.hwndOwner = hWnd;
            bi.lpszTitle = "Select folder";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI | BIF_EDITBOX;
            LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
            if (pidl) {
                if (SHGetPathFromIDListA(pidl, buf)) {
                    SetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PATH), buf);
                }
                CoTaskMemFree(pidl);
            }
            return 0;
        } else if (id == IDOK) {
            SetWindowLongPtrA(hWnd, GWLP_USERDATA, 1);
            PostQuitMessage(0);
            return 0;
        } else if (id == IDCANCEL) {
            SetWindowLongPtrA(hWnd, GWLP_USERDATA, 0);
            PostQuitMessage(0);
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

std::string PromptForFolder(const std::string& title, const std::string& initial) {
    const char* cls = "CustomFolderDlgClass";
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = CustomFolderWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = cls;
    RegisterClassExA(&wc);

    int width = 520, height = 140;
    HWND hWnd = CreateWindowExA(0, cls, title.c_str(), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, width, height, NULL, NULL, GetModuleHandleA(NULL), NULL);
    if (!hWnd) return std::string();

    HWND hedit = CreateWindowExA(0, "EDIT", initial.c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
        12, 12, 380, 22, hWnd, (HMENU)IDC_EDIT_PATH, GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        404, 10, 88, 24, hWnd, (HMENU)IDC_BUTTON_BROWSE, GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "Include system modules (C:\\Windows)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        12, 44, 380, 20, hWnd, (HMENU)IDC_CHECK_INCLUDE, GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        340, 84, 80, 26, hWnd, (HMENU)IDOK, GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        428, 84, 80, 26, hWnd, (HMENU)IDCANCEL, GetModuleHandleA(NULL), NULL);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    LONG_PTR ok = GetWindowLongPtrA(hWnd, GWLP_USERDATA);
    char path[MAX_PATH] = {0};
    GetWindowTextA(hedit, path, sizeof(path));
    BOOL include = (IsDlgButtonChecked(hWnd, IDC_CHECK_INCLUDE) == BST_CHECKED);
    DestroyWindow(hWnd);
    UnregisterClassA(cls, GetModuleHandleA(NULL));

    g_include_system_modules = (include != FALSE);
    if (ok == 1) return std::string(path);
    return std::string();
}

// forward declare window proc for dump choice dialog
static LRESULT CALLBACK DumpChoiceWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Simple modal dialog with a combobox to choose dump type.
// Returns: 0 = small, 1 = full, -1 = cancelled
static int ShowDumpChoiceDialog(HWND owner) {
    const char* clsName = "DumpChoiceWndClass";
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DumpChoiceWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = clsName;
    RegisterClassExA(&wc);

    int width = 420, height = 140;
    HWND hWnd = CreateWindowExA(0, clsName, "Select dump type", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, width, height, owner, NULL, GetModuleHandleA(NULL), NULL);
    if (!hWnd) return -1;

    // Label
    CreateWindowExA(0, "STATIC", "Choose dump type to use for this session:", WS_CHILD | WS_VISIBLE,
        12, 12, 380, 20, hWnd, NULL, GetModuleHandleA(NULL), NULL);
    // Combobox
    HWND cb = CreateWindowExA(0, "COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        12, 36, 380, 200, hWnd, (HMENU)1001, GetModuleHandleA(NULL), NULL);
    SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)"Small (MiniDumpNormal) - fast, small files");
    SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)"Full (FullMemory) - heavy, detailed");
    SendMessageA(cb, CB_SETCURSEL, 0, 0);

    // OK / Cancel
    CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        220, 80, 80, 26, hWnd, (HMENU)IDOK, GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        312, 80, 80, 26, hWnd, (HMENU)IDCANCEL, GetModuleHandleA(NULL), NULL);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // Modal message loop until PostQuitMessage from wndproc
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    // retrieve selection
    LONG_PTR data = GetWindowLongPtrA(hWnd, GWLP_USERDATA);
    int result = -1;
    if (data > 0) result = (int)data - 1; // convert back

    DestroyWindow(hWnd);
    UnregisterClassA(clsName, GetModuleHandleA(NULL));
    return result;
}

static LRESULT CALLBACK DumpChoiceWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK) {
            HWND cb = GetDlgItem(hWnd, 1001);
            int sel = (int)SendMessageA(cb, CB_GETCURSEL, 0, 0);
            SetWindowLongPtrA(hWnd, GWLP_USERDATA, sel + 1);
            PostQuitMessage(0);
            return 0;
        } else if (id == IDCANCEL) {
            SetWindowLongPtrA(hWnd, GWLP_USERDATA, 0);
            PostQuitMessage(0);
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        SetWindowLongPtrA(hWnd, GWLP_USERDATA, 0);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

// Return the base folder to use for dumps/logs. Will prompt user if not configured via env.
std::string GetBaseFolder() {
    // protect gBaseFolder initialization
    EnterCriticalSection(&g_base_cs);
    if (!gBaseFolder.empty()) { LeaveCriticalSection(&g_base_cs); return gBaseFolder; }
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
    // Only echo dynamic messages to the console — do not create a separate
    // "*_dynamic.log" file as requested.
    if (!g_writes_enabled) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

DWORD WINAPI InitThreadProc(LPVOID lpParam) {
    // Initialization thread
    AllocConsole();
    FILE* _conout = NULL;
    freopen_s(&_conout, "CONOUT$", "w", stdout);
    // Initialize processExeDir before any logging so GetBaseFolder can prompt with a sensible initial path
    processExeDir = GetProcessExeDir();
    // Initialize critical section used for base folder initialization
    InitializeCriticalSection(&g_base_cs);

    // Force base folder selection now (prompt if not configured via env). If user cancels, disable writes.
    std::string forcedBase = GetBaseFolder();
    if (forcedBase.empty()) {
        // User cancelled or no folder available: disable disk writes and exit init thread
        g_writes_enabled = false;
        printf("[Init] No base folder selected. Disk writes disabled.\n");
        return 0;
    }

    // Ensure required subfolders exist immediately so dynamic/static dumps can be created
    // without relying on the worker path. This prevents "missing dynamic" folder issues.
    EnsureBaseAndSubfolders(forcedBase);
    log_to_file("[Init] Ensured base and subfolders: %s", forcedBase.c_str());
    // quick test write
    if (!TestWriteAccess(forcedBase)) {
        printf("[Init] Warning: cannot write to base folder %s\n", forcedBase.c_str()); fflush(stdout);
        log_to_file("[Init] Warning: TestWriteAccess failed for %s", forcedBase.c_str());
    }

    // Ask user which dump type to use (small / full) after folder selection
    int choice = ShowDumpChoiceDialog(NULL);
    if (choice >= 0) {
        g_dump_choice = choice;
        if (g_dump_choice == 0) printf("[Init] Dump choice: SMALL\n");
        else printf("[Init] Dump choice: FULL\n");
        fflush(stdout);
        log_to_file("[Init] Dump choice set to %d", g_dump_choice);
    } else {
        // leave as default (-1) to allow env var to decide
        printf("[Init] Dump choice dialog cancelled, using defaults/env\n"); fflush(stdout);
    }

    // start background worker event and thread for non-blocking dynamic dumps
    InitializeCriticalSection(&g_queue_cs);
    g_worker_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (g_worker_event) {
        g_worker_running.store(true);
        g_worker_thread = CreateThread(NULL, 0, WorkerThreadProc, NULL, 0, NULL);
        if (g_worker_thread) SetThreadPriority(g_worker_thread, THREAD_PRIORITY_LOWEST);
    }
    // create event used to wait for related dynamic dump completion
    g_dynamic_done_event = CreateEventA(NULL, TRUE, FALSE, NULL);

    // (force base selection was done earlier)
    printf("------------------------------ STARTING HOOKING (init thread) -------------------------------\n");
    log_to_file("------------------------------ STARTING HOOKING (init thread) -------------------------------");
    printf("[Init] Process exe dir: %s\n", processExeDir.c_str());
    log_to_file("[Init] Process exe dir: %s", processExeDir.c_str());

    // Store modules and perform scans (single pass)
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

    // Produce a fast related-only dynamic dump right after hooks are installed so
    // the first dynamic snapshot is available immediately (avoids waiting for a
    // runtime event). Instead of launching a separate thread we enqueue a
    // special request into the existing worker queue so all dump IO happens
    // sequentially on the single consumer worker (avoids races and phantom
    // scheduling logs).
    if (g_dynamic_fulldump_written.exchange(true) == false) {
        // Produce the first related dynamic dump synchronously (same method as static)
        // to guarantee ordering and identical console/log behaviour.
        g_dynamic_dump_in_progress.store(true);
        DumpRelatedModulesDynamic();
        // write the textual process info after the dump (synchronous)
        WriteDynamicProcessInfoImmediate();
        g_dynamic_dump_in_progress.store(false);
    }

    // Start scheduler thread
    if (!g_dynamic_scheduler_running.load()) {
        g_dynamic_scheduler_running.store(true);
        g_dynamic_scheduler_thread = CreateThread(NULL, 0, SchedulerThreadProc, NULL, 0, NULL);
        if (g_dynamic_scheduler_thread) SetThreadPriority(g_dynamic_scheduler_thread, THREAD_PRIORITY_LOWEST);
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
        // enqueue for background processing (sequential queue)
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
        DumpRegionImmediate(r);
    }
    return res;
}

DWORD WINAPI ScannerThreadProc(LPVOID) {
    // Single pass scanner (no periodic sleeps) as requested: perform scans once and exit
    if (g_run_scanner) {
        StoreModuleRanges();
        ScanExportedFunctionTargets();
        ScanExecutablePagesAndDump();
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
                    log_to_file("Found executable module region (related) base=0x%p size=0x%lx module=%s", mbi.BaseAddress, (unsigned long)mbi.RegionSize, name.c_str());
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
                log_to_file("Found executable anonymous region base=0x%p size=0x%lx", mbi.BaseAddress, (unsigned long)mbi.RegionSize);
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
    // For compatibility keep function but do not perform heavy IO here.
    // Instead enqueue the region for the background worker which will create a
    // full minidump for the region.
    QNode* n = new QNode(); n->region = region; n->next = nullptr;
    EnterCriticalSection(&g_queue_cs);
    if (g_queue_tail) {
        g_queue_tail->next = n;
        g_queue_tail = n;
    } else {
        g_queue_head = g_queue_tail = n;
    }
    LeaveCriticalSection(&g_queue_cs);
    if (g_worker_event) SetEvent(g_worker_event);
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
    if (!g_include_system_modules && IsSystemModule(path)) return false;
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
                    log_to_file("Module: %s", modName);
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
        // Static dump: keep original behavior — produce the full/process dump (may be large)
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

// Callback to filter modules when creating a minidump so we include only modules
// related to the injected process. Called by MiniDumpWriteDump when the callback
// information is provided.
BOOL CALLBACK MiniDumpFilterCallback(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    // Keep default behavior: do not exclude modules from the related dynamic dump.
    // Returning TRUE without modifying ModuleWriteFlags ensures kernel/system
    // modules and all loaded modules are included in the minidump.
    if (!CallbackInput || !CallbackOutput) return FALSE;
    return TRUE;
}

// Produce a dynamic full dump but only including modules related to the injected
// process (uses MiniDump callback filtering). Writes to dynamic folder.
void DumpRelatedModulesDynamic() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = GetCurrentProcess();
    std::string base = GetBaseFolder();
    if (base.empty()) return;
    std::string dynamicFolder = base + "\\dynamic";
    EnsureBaseAndSubfolders(base);
    std::string outFile = dynamicFolder + "\\" + std::to_string(pid) + "_dynamic_related.dmp";
    HANDLE hFile = CreateFileA(outFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        dynamic_log("Related dynamic dump file open failed: %s err=%lu", outFile.c_str(), err);
        return;
    }
    MINIDUMP_CALLBACK_INFORMATION mci = {0};
    mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MiniDumpFilterCallback;
    mci.CallbackParam = NULL;
    // diagnostic: announce start. Log full path to hooklog, keep short name on console.
    std::string outName = BaseName(outFile);
    log_to_file("DumpRelatedModulesDynamic started for pid=%lu out=%s", pid, outFile.c_str());
    dynamic_log("DumpRelatedModulesDynamic started (out=%s)", outName.c_str());
    // Print the same info to console quickly (modules, exports, memory regions, threads)
    // do not print dynamic details to console
    // enumerate modules
    DWORD required2 = 0;
    if (EnumProcessModulesEx(hProcess, NULL, 0, &required2, LIST_MODULES_ALL) && required2 > 0) {
        size_t nm = required2 / sizeof(HMODULE);
        std::vector<HMODULE> mods2(nm);
        if (EnumProcessModulesEx(hProcess, mods2.data(), (DWORD)(nm * sizeof(HMODULE)), &required2, LIST_MODULES_ALL)) {
            size_t am = required2 / sizeof(HMODULE);
            for (size_t i = 0; i < am; ++i) {
                MODULEINFO mi = {0}; char mname[MAX_PATH] = {0};
                GetModuleInformation(hProcess, mods2[i], &mi, sizeof(mi));
                GetModuleFileNameExA(hProcess, mods2[i], mname, sizeof(mname));
                dynamic_log("Module: %s", mname);
                dynamic_log("  Base: %p Size: %lu", mi.lpBaseOfDll, (unsigned long)mi.SizeOfImage);
                // list exports (best-effort)
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
                            for (DWORD ni = 0; ni < exp->NumberOfNames; ++ni) {
                                const char* en = (const char*)(base + names[ni]);
                                WORD oi = ords[ni]; DWORD rva = funcs[oi];
                                dynamic_log("    Export: %s (ord=%u) rva=0x%08x", en, (unsigned int)(oi + exp->Base), rva);
                            }
                        }
                    }
                }
            }
        }
    }
    // memory regions (print summary)
    // memory regions summary (logged via dynamic_log only)
    SYSTEM_INFO si2; GetSystemInfo(&si2);
    BYTE* a = (BYTE*)si2.lpMinimumApplicationAddress; BYTE* ma = (BYTE*)si2.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi2;
    while (a < ma) {
        if (VirtualQuery(a, &mbi2, sizeof(mbi2)) == sizeof(mbi2)) {
            dynamic_log("  Base=%p Size=%zu State=%u Protect=%u Type=%u", mbi2.BaseAddress, (size_t)mbi2.RegionSize, (unsigned)mbi2.State, (unsigned)mbi2.Protect, (unsigned)mbi2.Type);
            a = (BYTE*)mbi2.BaseAddress + mbi2.RegionSize;
        } else break;
    }
    // threads
    // threads summary (logged via dynamic_log only)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do { if (te.th32OwnerProcessID == pid) dynamic_log("  ThreadID: %lu", te.th32ThreadID); } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    // Choose minidump type. Use the same (full) flags as static dumps by default
    // so dynamic related dumps are produced the same way unless the user
    // explicitly selected a small dump in the UI.
    MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory);
    if (g_dump_choice == 0) {
        // user explicitly chose small/minimal dynamic dumps
        mdt = MiniDumpNormal;
    }
    log_to_file("Starting related dynamic dump (fast): %s", outFile.c_str());
    dynamic_log("Starting related dynamic dump (fast): %s", outName.c_str());
    BOOL ok = MiniDumpWriteDump(hProcess, pid, hFile, mdt, NULL, NULL, &mci);
    CloseHandle(hFile);
    if (ok) {
        log_to_file("Related dynamic minidump created: %s", outFile.c_str());
        dynamic_log("Related dynamic minidump created: %s", outName.c_str());
        // do not create an index file for dynamic dumps as requested by the user
        // Final single-line success summary (dynamic_log only)
        dynamic_log("ALL DONE: dynamic related dump completed successfully: %s", outName.c_str());
    } else {
        DWORD err = GetLastError();
        log_to_file("Failed to create related dynamic minidump: %s err=%lu", outFile.c_str(), err);
        dynamic_log("Failed to create related dynamic minidump: %s err=%lu", outName.c_str(), err);
        // Final single-line failure summary
        log_to_file("ALL DONE: dynamic related dump failed: %s err=%lu", outFile.c_str(), err);
        dynamic_log("ALL DONE: dynamic related dump failed: %s err=%lu", outName.c_str(), err);
    }
}

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
                    // Determine if the region belongs to any loaded module.
                    // If it belongs to an unrelated/system module, skip — do not treat as shellcode.
                    uintptr_t regionAddr = (uintptr_t)mbi.BaseAddress;
                    bool belongsToSomeModule = false;
                    bool belongsToRelatedModule = false;
                    for (const auto& mod : moduleRangesAll) {
                        uintptr_t base = (uintptr_t)mod.first;
                        uintptr_t size = mod.second;
                        if (regionAddr >= base && regionAddr < base + size) {
                            belongsToSomeModule = true;
                            // check if this module is in the related list
                            for (const auto& rmod : moduleRanges) {
                                uintptr_t rbase = (uintptr_t)rmod.first;
                                uintptr_t rsize = rmod.second;
                                if (regionAddr >= rbase && regionAddr < rbase + rsize) { belongsToRelatedModule = true; break; }
                            }
                            break;
                        }
                    }

                    // Only consider as shellcode if it does NOT belong to any module.
                    if (!belongsToSomeModule) {
                        DumpRegion r = {mbi.BaseAddress, mbi.RegionSize, name};
                        // enqueue for background processing
                        // enqueue into sequential queue
                        QNode* n = new QNode(); n->region = r; n->next = nullptr;
                        EnterCriticalSection(&g_queue_cs);
                        if (g_queue_tail) { g_queue_tail->next = n; g_queue_tail = n; }
                        else { g_queue_head = g_queue_tail = n; }
                        LeaveCriticalSection(&g_queue_cs);
                        if (g_worker_event) SetEvent(g_worker_event);
                        // Log detection immediately to console and file so dynamic activity is visible
                        printf("[DynamicDump] Detected region %s (base=0x%p, size=0x%lx)\n", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        log_to_file("[DynamicDump] Detected region %s (base=0x%p, size=0x%lx)", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        // Also append a short textual line into the dynamic dump file for immediate visibility
                        dynamic_log("[DynamicDump] DETECT %s base=0x%p size=0x%lx", name.c_str(), mbi.BaseAddress, (unsigned long)mbi.RegionSize);
                        // Also dump immediately to ensure we capture even if DLL is not unloaded
                        DumpRegionImmediate(r);
                    } else {
                        // region belongs to a module. If it's related we ignore (module code already handled by static scan),
                        // if it's unrelated/system module we should also ignore to avoid per-line dumps of system DLLs.
                        // Nothing to do here.
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
                std::string modPath = modName;
                // Always record all modules for ownership checks
                moduleRangesAll[(void*)modInfo.lpBaseOfDll] = modInfo.SizeOfImage;
                modulePaths[(void*)modInfo.lpBaseOfDll] = modPath;
                // Only keep a separate map of modules related to the injected process
                if (IsModuleRelatedToProcess(modName)) {
                    moduleRanges[(void*)modInfo.lpBaseOfDll] = modInfo.SizeOfImage;
                    printf("[StoreModuleRanges] Module (related): %s (base=0x%p, size=0x%lx)\n", modName, modInfo.lpBaseOfDll, (unsigned long)modInfo.SizeOfImage);
                    log_to_file("[StoreModuleRanges] Module (related): %s (base=0x%p, size=0x%lx)", modName, modInfo.lpBaseOfDll, (unsigned long)modInfo.SizeOfImage);
                } else {
                    // record system/unrelated modules too (quiet log)
                    log_to_file("[StoreModuleRanges] Module (unrelated): %s (base=0x%p, size=0x%lx)", modName, modInfo.lpBaseOfDll, (unsigned long)modInfo.SizeOfImage);
                }
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

        // Signal and stop background worker
        if (g_worker_event) SetEvent(g_worker_event);
        if (g_worker_thread) {
            WaitForSingleObject(g_worker_thread, 5000);
            CloseHandle(g_worker_thread);
            g_worker_thread = NULL;
        }
        // clean queue critical section
        EnterCriticalSection(&g_queue_cs);
        QNode* nnode = g_queue_head;
        while (nnode) { QNode* n = nnode->next; delete nnode; nnode = n; }
        g_queue_head = g_queue_tail = nullptr;
        LeaveCriticalSection(&g_queue_cs);
        DeleteCriticalSection(&g_queue_cs);
        // Stop dynamic scheduler
        if (g_dynamic_scheduler_thread) {
            g_dynamic_scheduler_running.store(false);
            WaitForSingleObject(g_dynamic_scheduler_thread, 5000);
            CloseHandle(g_dynamic_scheduler_thread);
            g_dynamic_scheduler_thread = NULL;
        }
        if (g_worker_event) { CloseHandle(g_worker_event); g_worker_event = NULL; }
        if (g_dynamic_done_event) { CloseHandle(g_dynamic_done_event); g_dynamic_done_event = NULL; }
        // delete critical section
        DeleteCriticalSection(&g_base_cs);
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
