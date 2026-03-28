#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* fn_rtlrb_insert)(void* tree, void* parent, BOOLEAN right, void* node);
typedef BOOLEAN(NTAPI* fn_rtladd_function_table)(void* table, ULONG count, ULONG64 base);
typedef NTSTATUS(NTAPI* fn_ldrp_handle_tls)(void* entry);
typedef int (*fn_entry_point)(void);

typedef BOOL(WINAPI* fn_getmodulehandleexw)(DWORD flags, LPCWSTR name, HMODULE* out);

static uintptr_t g_imagebase;
static uint32_t g_imagesize;
static fn_getmodulehandleexw g_orig_gmhe;

static BOOL WINAPI gmhe_hook(DWORD flags, LPCWSTR name, HMODULE* out) {
    if ((flags & 0x04) && name) {
        uintptr_t addr = (uintptr_t)name;
        if (addr >= g_imagebase && addr < g_imagebase + g_imagesize) {
            *out = (HMODULE)g_imagebase;
            return TRUE;
        }
    }
    return g_orig_gmhe(flags, name, out);
}

static uint32_t ldr_hash(const wchar_t* name) {
    uint32_t hash = 0;
    while (*name) {
        wchar_t c = *name++;
        if (c >= L'a' && c <= L'z') c -= 0x20;
        hash = hash * 65599 + c;
    }
    return hash;
}

static void link_list(uint8_t* entry_links, uint8_t* list_head) {
    uintptr_t* head_flink = (uintptr_t*)list_head;
    uintptr_t* head_blink = (uintptr_t*)(list_head + 8);
    uintptr_t* our_flink = (uintptr_t*)entry_links;
    uintptr_t* our_blink = (uintptr_t*)(entry_links + 8);

    uint8_t* old_last = (uint8_t*)*head_blink;
    *our_flink = (uintptr_t)list_head;
    *our_blink = (uintptr_t)old_last;
    *(uintptr_t*)old_last = (uintptr_t)entry_links;
    *head_blink = (uintptr_t)entry_links;
}

static uint32_t section_protection(uint32_t chars) {
    bool exec = (chars & 0x20000000) != 0;
    bool read = (chars & 0x40000000) != 0;
    bool write = (chars & 0x80000000) != 0;

    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static bool map_sections(uint8_t* base, uint8_t* pe, int section_start, int num_sections) {
    for (int i = 0; i < num_sections; i++) {
        uint8_t* shdr = pe + section_start + i * 40;
        uint32_t vsize   = *(uint32_t*)(shdr + 8);
        uint32_t va      = *(uint32_t*)(shdr + 12);
        uint32_t rawsize = *(uint32_t*)(shdr + 16);
        uint32_t rawptr  = *(uint32_t*)(shdr + 20);

        if (rawsize > 0 && rawptr > 0) {
            uint32_t copysize = rawsize < vsize ? rawsize : vsize;
            memcpy(base + va, pe + rawptr, copysize);
        }
    }
    return true;
}

static bool apply_relocations(uint8_t* base, uint32_t reloc_rva, uint32_t reloc_size) {
    int32_t e_lfanew = *(int32_t*)(base + 0x3C);
    uint64_t orig_base = *(uint64_t*)(base + e_lfanew + 24 + 24);
    int64_t delta = (int64_t)((uintptr_t)base - orig_base);

    if (delta == 0) return true;

    uint32_t offset = 0;
    while (offset < reloc_size) {
        uint8_t* block = base + reloc_rva + offset;
        uint32_t block_rva  = *(uint32_t*)block;
        uint32_t block_size = *(uint32_t*)(block + 4);

        if (block_size == 0) break;

        uint32_t num_entries = (block_size - 8) / 2;
        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry = *(uint16_t*)(block + 8 + i * 2);
            uint16_t type = entry >> 12;
            uint16_t off  = entry & 0xFFF;

            if (type == 10) {
                int64_t* patch = (int64_t*)(base + block_rva + off);
                *patch += delta;
            } else if (type != 0) {
                return false;
            }
        }
        offset += block_size;
    }
    return true;
}

static bool resolve_imports(uint8_t* base, uint32_t import_rva) {
    uint32_t offset = 0;
    while (true) {
        uint8_t* desc = base + import_rva + offset;
        uint32_t oft      = *(uint32_t*)(desc);
        uint32_t name_rva = *(uint32_t*)(desc + 12);
        uint32_t ft       = *(uint32_t*)(desc + 16);

        if (name_rva == 0) break;

        const char* dllname = (const char*)(base + name_rva);
        HMODULE hmod = LoadLibraryA(dllname);
        if (!hmod) {
            printf("failed to load %s\n", dllname);
            return false;
        }

        uint32_t thunk_rva = (oft != 0) ? oft : ft;
        uint32_t iat_rva = ft;
        uint32_t idx = 0;

        while (true) {
            uint64_t thunkval = *(uint64_t*)(base + thunk_rva + idx * 8);
            if (thunkval == 0) break;

            FARPROC resolved;
            if (thunkval & (1ULL << 63)) {
                resolved = GetProcAddress(hmod, (LPCSTR)(thunkval & 0xFFFF));
            } else {
                const char* funcname = (const char*)(base + (uint32_t)(thunkval & 0x7FFFFFFF) + 2);
                resolved = GetProcAddress(hmod, funcname);
            }

            if (!resolved) {
                printf("unresolved import from %s\n", dllname);
                return false;
            }

            *(uint64_t*)(base + iat_rva + idx * 8) = (uint64_t)resolved;
            idx++;
        }
        offset += 20;
    }
    return true;
}

static uint8_t* get_peb() {
    return (uint8_t*)__readgsqword(0x60);
}

static uint8_t* create_ldr_entry(uint8_t* imagebase, uint32_t sizeofimage,
                                  uint32_t ep_rva, uint64_t original_base,
                                  uint32_t timedatestamp) {
    uint8_t* entry = (uint8_t*)VirtualAlloc(nullptr, 0x200,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!entry) return nullptr;

    uint8_t* ddag = (uint8_t*)VirtualAlloc(nullptr, 0x60,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ddag) return nullptr;

    static wchar_t fullpath[] = L"\\??\\C:\\Windows\\System32\\nativeaot_module.dll";
    static wchar_t basename[] = L"nativeaot_module.dll";

    *(uintptr_t*)(entry + 0x30) = (uintptr_t)imagebase;
    *(uintptr_t*)(entry + 0x38) = (uintptr_t)(imagebase + ep_rva);
    *(uint32_t*)(entry + 0x40)  = sizeofimage;

    *(uint16_t*)(entry + 0x48)   = (uint16_t)(wcslen(fullpath) * 2);
    *(uint16_t*)(entry + 0x4A)   = (uint16_t)((wcslen(fullpath) + 1) * 2);
    *(uintptr_t*)(entry + 0x50)  = (uintptr_t)fullpath;

    *(uint16_t*)(entry + 0x58)   = (uint16_t)(wcslen(basename) * 2);
    *(uint16_t*)(entry + 0x5A)   = (uint16_t)((wcslen(basename) + 1) * 2);
    *(uintptr_t*)(entry + 0x60)  = (uintptr_t)basename;

    *(uint32_t*)(entry + 0x68)  = 0x000CAAC4;
    *(uint16_t*)(entry + 0x6C)  = 0xFFFF;
    *(uint16_t*)(entry + 0x6E)  = 0;

    *(uintptr_t*)(entry + 0x70) = (uintptr_t)(entry + 0x70);
    *(uintptr_t*)(entry + 0x78) = (uintptr_t)(entry + 0x70);

    *(uint32_t*)(entry + 0x80)  = timedatestamp;

    *(uintptr_t*)(entry + 0x88) = 0;
    *(uintptr_t*)(entry + 0x90) = 0;

    *(uintptr_t*)(entry + 0x98) = (uintptr_t)ddag;

    *(uintptr_t*)(entry + 0xA0) = (uintptr_t)(ddag + 0x00);
    *(uintptr_t*)(entry + 0xA8) = (uintptr_t)(ddag + 0x00);

    *(uintptr_t*)(entry + 0xB0) = 0;
    *(uintptr_t*)(entry + 0xB8) = 0;
    *(uintptr_t*)(entry + 0xC0) = 0;

    *(uintptr_t*)(entry + 0xC8) = 0;
    *(uintptr_t*)(entry + 0xD0) = 0;
    *(uintptr_t*)(entry + 0xD8) = 0;

    *(uintptr_t*)(entry + 0xE0) = 0;
    *(uintptr_t*)(entry + 0xE8) = 0;
    *(uintptr_t*)(entry + 0xF0) = 0;

    *(uint64_t*)(entry + 0xF8)  = original_base;

    LARGE_INTEGER loadtime;
    QueryPerformanceCounter(&loadtime);
    *(int64_t*)(entry + 0x100)  = loadtime.QuadPart;

    *(uint32_t*)(entry + 0x108) = ldr_hash(basename);
    *(uint32_t*)(entry + 0x10C) = 4;
    *(uint32_t*)(entry + 0x110) = 0;
    *(uint32_t*)(entry + 0x114) = 1;
    *(uint32_t*)(entry + 0x118) = 0;
    *(uint8_t*)(entry + 0x11C)  = 0;

    *(uintptr_t*)(ddag + 0x00) = (uintptr_t)(entry + 0xA0);
    *(uintptr_t*)(ddag + 0x08) = (uintptr_t)(entry + 0xA0);
    *(uintptr_t*)(ddag + 0x10) = 0;
    *(uint32_t*)(ddag + 0x18)  = 1;
    *(uint32_t*)(ddag + 0x1C)  = 0;
    *(uint32_t*)(ddag + 0x20)  = 0;
    *(uintptr_t*)(ddag + 0x28) = 0;
    *(uintptr_t*)(ddag + 0x30) = 0;
    *(uint32_t*)(ddag + 0x38)  = 9;
    *(uintptr_t*)(ddag + 0x40) = 0;
    *(uint32_t*)(ddag + 0x48)  = 0;

    return entry;
}

static void link_into_peb(uint8_t* entry) {
    uint8_t* peb = get_peb();
    if (!peb) return;

    uint8_t* ldr = *(uint8_t**)(peb + 0x18);

    link_list(entry + 0x00, ldr + 0x10);
    link_list(entry + 0x10, ldr + 0x20);
    link_list(entry + 0x20, ldr + 0x30);
}

// walk RTL_BALANCED_NODE parent pointers (ParentValue & ~7) up to root (ParentValue == 0)
static uint8_t* walk_to_root(uint8_t* node) {
    uint8_t* current = node;
    for (int i = 0; i < 256; i++) {
        uintptr_t parent_val = *(uintptr_t*)(current + 0x10);
        uintptr_t parent_ptr = parent_val & ~(uintptr_t)7;
        if (parent_ptr == 0)
            return current;
        current = (uint8_t*)parent_ptr;
    }
    return current;
}

static uint8_t* find_tree_in_ntdll(uint8_t* ntdll, uint8_t* root_node) {
    int32_t e_lfanew = *(int32_t*)(ntdll + 0x3C);
    uint16_t num_sections = *(uint16_t*)(ntdll + e_lfanew + 6);
    uint16_t opt_size = *(uint16_t*)(ntdll + e_lfanew + 20);
    int section_start = e_lfanew + 24 + opt_size;

    for (int i = 0; i < num_sections; i++) {
        uint8_t* shdr = ntdll + section_start + i * 40;
        if (shdr[0] == '.' && shdr[1] == 'd' && shdr[2] == 'a' &&
            shdr[3] == 't' && shdr[4] == 'a' && shdr[5] == 0) {

            uint32_t data_rva   = *(uint32_t*)(shdr + 12);
            uint32_t data_vsize = *(uint32_t*)(shdr + 8);
            uint8_t* data_start = ntdll + data_rva;
            uintptr_t target = (uintptr_t)root_node;

            for (uint32_t off = 0; off + 16 <= data_vsize; off += 8) {
                if (*(uintptr_t*)(data_start + off) == target)
                    return data_start + off;
            }
        }
    }
    return nullptr;
}

// walk RB tree comparing DllBase (node - 0xC8 + 0x30 = node - 0x98) to find insertion point,
// then call RtlRbInsertNodeEx
static bool insert_baseaddress_tree(uint8_t* entry, uint8_t* imagebase) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    fn_rtlrb_insert rtlrb = (fn_rtlrb_insert)GetProcAddress(ntdll, "RtlRbInsertNodeEx");
    if (!rtlrb) return false;

    uint8_t* peb = get_peb();
    if (!peb) return false;

    uint8_t* ldr = *(uint8_t**)(peb + 0x18);
    uint8_t* head = ldr + 0x10;
    uint8_t* current = *(uint8_t**)head;

    uint8_t* known_entry = nullptr;
    while (current != head) {
        uintptr_t dllbase = *(uintptr_t*)(current + 0x30);
        if (dllbase == (uintptr_t)ntdll) {
            known_entry = current;
            break;
        }
        current = *(uint8_t**)current;
    }

    if (!known_entry) {
        current = *(uint8_t**)head;
        if (current != head)
            known_entry = current;
    }

    if (!known_entry) return false;

    uint8_t* known_node = known_entry + 0xC8;
    uint8_t* root_node = walk_to_root(known_node);
    if (!root_node) return false;

    uint8_t* tree_addr = find_tree_in_ntdll((uint8_t*)ntdll, root_node);
    if (!tree_addr) return false;

    printf("baseaddressindex tree at 0x%llx\n", (unsigned long long)(uintptr_t)tree_addr);

    uint8_t* our_node = entry + 0xC8;
    uintptr_t our_base = (uintptr_t)imagebase;

    uint8_t* parent = nullptr;
    BOOLEAN right = FALSE;
    uint8_t* walk = root_node;

    while (walk) {
        parent = walk;
        uintptr_t node_dllbase = *(uintptr_t*)(walk - 0xC8 + 0x30);

        if (our_base < node_dllbase) {
            right = FALSE;
            walk = *(uint8_t**)walk;
        } else {
            right = TRUE;
            walk = *(uint8_t**)(walk + 8);
        }
    }

    rtlrb(tree_addr, parent, right, our_node);
    return true;
}

static void install_gmhe_hook(uint8_t* imagebase, uint32_t import_rva, uint32_t sizeofimage) {
    g_imagebase = (uintptr_t)imagebase;
    g_imagesize = sizeofimage;

    HMODULE k32 = LoadLibraryA("kernel32.dll");
    g_orig_gmhe = (fn_getmodulehandleexw)GetProcAddress(k32, "GetModuleHandleExW");

    if (import_rva == 0) {
        printf("no imports to hook\n");
        return;
    }

    uint32_t idt_offset = 0;
    while (true) {
        uint32_t oft      = *(uint32_t*)(imagebase + import_rva + idt_offset);
        uint32_t name_rva = *(uint32_t*)(imagebase + import_rva + idt_offset + 12);
        uint32_t ft_rva   = *(uint32_t*)(imagebase + import_rva + idt_offset + 16);

        if (name_rva == 0) break;

        const char* dll = (const char*)(imagebase + name_rva);
        bool is_k32 = false;
        for (const char* p = dll; *p; p++) {
            if ((p[0] | 0x20) == 'k' && (p[1] | 0x20) == 'e' && (p[2] | 0x20) == 'r' &&
                (p[3] | 0x20) == 'n' && (p[4] | 0x20) == 'e' && (p[5] | 0x20) == 'l' &&
                p[6] == '3' && p[7] == '2') {
                is_k32 = true;
                break;
            }
        }

        if (is_k32) {
            uint32_t thunk_rva = (oft != 0) ? oft : ft_rva;
            int idx = 0;
            while (true) {
                uint64_t thunkval = *(uint64_t*)(imagebase + thunk_rva + idx * 8);
                if (thunkval == 0) break;

                if ((thunkval & (1ULL << 63)) == 0) {
                    const char* fname = (const char*)(imagebase + (uint32_t)(thunkval & 0x7FFFFFFF) + 2);
                    if (strcmp(fname, "GetModuleHandleExW") == 0) {
                        uint8_t* iat_slot = imagebase + ft_rva + idx * 8;
                        DWORD old;
                        VirtualProtect(iat_slot, 8, PAGE_READWRITE, &old);
                        *(uintptr_t*)iat_slot = (uintptr_t)&gmhe_hook;
                        VirtualProtect(iat_slot, 8, old, &old);
                        printf("hooked getmodulehandleexw in iat\n");
                        return;
                    }
                }
                idx++;
            }
        }
        idt_offset += 20;
    }
    printf("getmodulehandleexw not found in iat\n");
}

// scan ntdll RUNTIME_FUNCTION entries for a function that calls all 4 target exports
// (RtlImageDirectoryEntryToData, RtlAcquireSRWLockExclusive, RtlAllocateHeap, memcpy)
// via E8 (CALL rel32) instructions - the smallest matching function is LdrpHandleTlsData
static void* find_ldrp_handle_tls_data() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) return nullptr;

    uint8_t* ntdll_base = (uint8_t*)ntdll;

    uintptr_t t1 = (uintptr_t)GetProcAddress(ntdll, "RtlImageDirectoryEntryToData");
    uintptr_t t2 = (uintptr_t)GetProcAddress(ntdll, "RtlAcquireSRWLockExclusive");
    uintptr_t t3 = (uintptr_t)GetProcAddress(ntdll, "RtlAllocateHeap");
    uintptr_t t4 = (uintptr_t)GetProcAddress(ntdll, "RtlCopyMemory");
    if (!t4) t4 = (uintptr_t)GetProcAddress(ntdll, "memcpy");

    if (!t1 || !t2 || !t3 || !t4) {
        printf("missing ntdll exports for tls scan\n");
        return nullptr;
    }

    int32_t e_lfanew = *(int32_t*)(ntdll_base + 0x3C);
    uint16_t num_sections = *(uint16_t*)(ntdll_base + e_lfanew + 6);
    uint16_t opt_size = *(uint16_t*)(ntdll_base + e_lfanew + 20);
    int section_start = e_lfanew + 24 + opt_size;
    uint32_t numrva = *(uint32_t*)(ntdll_base + e_lfanew + 24 + 108);

    uint32_t text_rva = 0, text_vsize = 0;
    for (int i = 0; i < num_sections; i++) {
        uint8_t* shdr = ntdll_base + section_start + i * 40;
        if (shdr[0] == '.' && shdr[1] == 't' && shdr[2] == 'e' &&
            shdr[3] == 'x' && shdr[4] == 't') {
            text_vsize = *(uint32_t*)(shdr + 8);
            text_rva = *(uint32_t*)(shdr + 12);
            break;
        }
    }

    if (!text_rva || !text_vsize) {
        printf("ntdll .text not found\n");
        return nullptr;
    }

    uint32_t exc_rva = 0, exc_size = 0;
    if (numrva > 3) {
        exc_rva  = *(uint32_t*)(ntdll_base + e_lfanew + 24 + 136);
        exc_size = *(uint32_t*)(ntdll_base + e_lfanew + 24 + 140);
    }

    if (!exc_rva || !exc_size) {
        printf("ntdll exception directory not found\n");
        return nullptr;
    }

    uint8_t* text = ntdll_base + text_rva;
    uint32_t rf_count = exc_size / 12;

    void* best = nullptr;
    uint32_t best_size = 0xFFFFFFFF;

    for (uint32_t rf = 0; rf < rf_count; rf++) {
        uint8_t* rf_ptr = ntdll_base + exc_rva + rf * 12;
        uint32_t func_begin = *(uint32_t*)rf_ptr;
        uint32_t func_end   = *(uint32_t*)(rf_ptr + 4);

        if (func_begin < text_rva || func_end > text_rva + text_vsize)
            continue;

        uint32_t func_size = func_end - func_begin;
        if (func_size < 64 || func_size > 0x3000)
            continue;

        bool hit1 = false, hit2 = false, hit3 = false, hit4 = false;
        uint32_t local_start = func_begin - text_rva;
        uint32_t local_end   = func_end - text_rva;

        if (local_end > text_vsize) continue;

        for (uint32_t i = local_start; i < local_end - 4; i++) {
            if (text[i] != 0xE8) continue;

            uintptr_t call_addr = (uintptr_t)(ntdll_base + text_rva + i);
            int32_t rel = *(int32_t*)(text + i + 1);
            uintptr_t target = call_addr + 5 + rel;

            if (target == t1) hit1 = true;
            else if (target == t2) hit2 = true;
            else if (target == t3) hit3 = true;
            else if (target == t4) hit4 = true;

            if (hit1 && hit2 && hit3 && hit4) {
                if (func_size < best_size) {
                    best = ntdll_base + func_begin;
                    best_size = func_size;
                }
                break;
            }
        }
    }
    return best;
}

static void set_section_protections(uint8_t* base, uint8_t* pe, int section_start, int num_sections) {
    for (int i = 0; i < num_sections; i++) {
        uint8_t* shdr = pe + section_start + i * 40;
        uint32_t vsize = *(uint32_t*)(shdr + 8);
        uint32_t va    = *(uint32_t*)(shdr + 12);
        uint32_t chars = *(uint32_t*)(shdr + 36);

        if (vsize == 0) continue;

        DWORD old;
        VirtualProtect(base + va, vsize, section_protection(chars), &old);
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("usage: nativeaot_loader.exe <pe_path>\n");
        return 1;
    }

    const char* pepath = argv[1];

    HANDLE file = CreateFileA(pepath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        printf("failed to open %s\n", pepath);
        return 1;
    }

    DWORD filesize = GetFileSize(file, nullptr);
    if (filesize == INVALID_FILE_SIZE || filesize < 64) {
        printf("invalid file size\n");
        CloseHandle(file);
        return 1;
    }

    uint8_t* pe = (uint8_t*)VirtualAlloc(nullptr, filesize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pe) {
        printf("alloc failed for file buffer\n");
        CloseHandle(file);
        return 1;
    }

    DWORD bytes_read;
    if (!ReadFile(file, pe, filesize, &bytes_read, nullptr) || bytes_read != filesize) {
        printf("failed to read file\n");
        CloseHandle(file);
        return 1;
    }
    CloseHandle(file);

    printf("loaded %u bytes\n", filesize);

    if (pe[0] != 0x4D || pe[1] != 0x5A) {
        printf("bad mz\n");
        return 1;
    }

    int32_t e_lfanew = *(int32_t*)(pe + 0x3C);
    if (e_lfanew + 4 > (int32_t)filesize || *(uint32_t*)(pe + e_lfanew) != 0x00004550) {
        printf("bad pe sig\n");
        return 1;
    }

    uint16_t num_sections = *(uint16_t*)(pe + e_lfanew + 6);
    uint16_t opt_size     = *(uint16_t*)(pe + e_lfanew + 20);
    int opthdr = e_lfanew + 24;

    if (*(uint16_t*)(pe + opthdr) != 0x20B) {
        printf("not pe32+\n");
        return 1;
    }

    uint32_t ep_rva         = *(uint32_t*)(pe + opthdr + 16);
    uint64_t preferred_base = *(uint64_t*)(pe + opthdr + 24);
    uint32_t sizeofimage    = *(uint32_t*)(pe + opthdr + 56);
    uint32_t sizeofheaders  = *(uint32_t*)(pe + opthdr + 60);
    uint32_t numrva         = *(uint32_t*)(pe + opthdr + 108);
    uint32_t timedatestamp   = *(uint32_t*)(pe + e_lfanew + 8);

    printf("pe32+ sections=%u imagesize=0x%x\n", num_sections, sizeofimage);

    uint32_t import_rva = 0, import_size = 0;
    if (numrva > 1) {
        import_rva  = *(uint32_t*)(pe + opthdr + 120);
        import_size = *(uint32_t*)(pe + opthdr + 124);
    }

    uint32_t exc_rva = 0, exc_size = 0;
    if (numrva > 3) {
        exc_rva  = *(uint32_t*)(pe + opthdr + 136);
        exc_size = *(uint32_t*)(pe + opthdr + 140);
    }

    uint32_t reloc_rva = 0, reloc_size = 0;
    if (numrva > 5) {
        reloc_rva  = *(uint32_t*)(pe + opthdr + 152);
        reloc_size = *(uint32_t*)(pe + opthdr + 156);
    }

    uint32_t tls_rva = 0, tls_size = 0;
    if (numrva > 9) {
        tls_rva  = *(uint32_t*)(pe + opthdr + 184);
        tls_size = *(uint32_t*)(pe + opthdr + 188);
    }

    uint8_t* imagebase = (uint8_t*)VirtualAlloc((void*)preferred_base, sizeofimage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!imagebase) {
        printf("preferred base unavailable, allocating elsewhere\n");
        imagebase = (uint8_t*)VirtualAlloc(nullptr, sizeofimage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!imagebase) {
        printf("alloc failed\n");
        return 1;
    }

    printf("mapped at 0x%llx\n", (unsigned long long)(uintptr_t)imagebase);

    memcpy(imagebase, pe, sizeofheaders);

    int section_start = e_lfanew + 24 + opt_size;
    map_sections(imagebase, pe, section_start, num_sections);
    printf("sections mapped\n");

    int64_t delta = (int64_t)((uintptr_t)imagebase - preferred_base);
    if (delta != 0 && reloc_rva != 0 && reloc_size != 0) {
        if (!apply_relocations(imagebase, reloc_rva, reloc_size)) {
            printf("relocations failed\n");
            return 1;
        }
        printf("relocations applied, delta=0x%llx\n", (unsigned long long)delta);
    } else if (delta == 0) {
        printf("at preferred base, no relocs needed\n");
    }

    if (import_rva != 0 && import_size != 0) {
        if (!resolve_imports(imagebase, import_rva)) {
            printf("imports failed\n");
            return 1;
        }
        printf("imports resolved\n");
    }

    bool ldr_ok = false;
    uint8_t* ldr_entry = create_ldr_entry(imagebase, sizeofimage, ep_rva,
        preferred_base, timedatestamp);

    if (ldr_entry) {
        link_into_peb(ldr_entry);
        printf("ldr entry linked into peb\n");

        bool tree_ok = insert_baseaddress_tree(ldr_entry, imagebase);
        if (tree_ok)
            printf("baseaddressindex tree insertion ok\n");
        else
            printf("baseaddressindex tree insertion failed, iat hook will compensate\n");

        ldr_ok = true;
    } else {
        printf("failed to create ldr entry\n");
    }

    install_gmhe_hook(imagebase, import_rva, sizeofimage);

    if (tls_rva != 0 && tls_size != 0) {
        if (ldr_ok) {
            void* ldrp = find_ldrp_handle_tls_data();
            if (ldrp) {
                printf("ldrphandletlsdata at 0x%llx\n", (unsigned long long)(uintptr_t)ldrp);
                fn_ldrp_handle_tls handler = (fn_ldrp_handle_tls)ldrp;
                NTSTATUS status = handler(ldr_entry);
                printf("ldrphandletlsdata returned 0x%08x\n", (uint32_t)status);
                if (status != 0) {
                    printf("tls setup failed\n");
                    return 1;
                }
                printf("tls configured\n");
            } else {
                printf("ldrphandletlsdata not found\n");
                return 1;
            }
        } else {
            printf("no ldr entry for tls\n");
            return 1;
        }
    }

    if (exc_rva != 0 && exc_size != 0) {
        uint32_t exc_count = exc_size / 12;
        BOOLEAN added = RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(imagebase + exc_rva), exc_count, (DWORD64)imagebase);
        printf("exception table: %u entries, registered=%d\n", exc_count, added);
    }

    set_section_protections(imagebase, pe, section_start, num_sections);
    printf("protections set\n");

    if (ep_rva == 0) {
        printf("no entry point\n");
        return 0;
    }

    void* ep = imagebase + ep_rva;
    printf("entry point at 0x%llx rva=0x%x\n", (unsigned long long)(uintptr_t)ep, ep_rva);
    printf("calling entry point\n");
    fflush(stdout);

    fn_entry_point entry = (fn_entry_point)ep;
    int result = entry();

    printf("entry point returned: %d\n", result);
    return result;
}
