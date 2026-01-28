#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

// --- Helpers ---

// Finds a PID by process name
pid_t find_pid(const char* name) {
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;
        
        char path[PATH_MAX], exe[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        
        ssize_t len = readlink(path, exe, sizeof(exe) - 1);
        if (len != -1) {
            exe[len] = '\0';
            if (strstr(exe, name)) {
                closedir(d);
                return pid;
            }
        }
    }
    closedir(d);
    return -1;
}

// Gets the base address of a loaded shared library in the target process
unsigned long get_module_base(pid_t pid, const char *name) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    unsigned long addr = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            addr = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return addr;
}

// Calculates the offset of a symbol in the local process
unsigned long get_offset(const char *lib, const char *sym) {
    void *h = dlopen(lib, RTLD_LAZY);
    if (!h) return 0;
    void *func_addr = dlsym(h, sym);
    unsigned long base_addr = get_module_base(getpid(), lib);
    dlclose(h);
    
    if (!func_addr || !base_addr) return 0;
    return (unsigned long)func_addr - base_addr;
}

// --- Injection Logic ---

void inject(pid_t pid, const char *lib_path) {
    printf("[*] Injecting %s into PID %d\n", lib_path, pid);
    
    struct user_regs_struct old_regs, regs;
    int status;

    // 1. Attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] Failed to attach");
        exit(EXIT_FAILURE);
    }
    waitpid(pid, &status, 0);

    // 2. Save Registers
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    memcpy(&regs, &old_regs, sizeof(regs));

    // 3. Resolve dlopen address
    // Note: We check both libc and libdl because modern glibc includes dlopen directly
    unsigned long libdl_base = get_module_base(pid, "libdl-");
    if (!libdl_base) libdl_base = get_module_base(pid, "libdl.so"); 
    
    unsigned long libc_base = get_module_base(pid, "libc-");
    if (!libc_base) libc_base = get_module_base(pid, "libc.so");

    unsigned long target_dlopen = 0;
    
    // Try to find dlopen in libdl first, then libc
    if (libdl_base) {
        target_dlopen = libdl_base + get_offset("libdl.so.2", "dlopen");
    } 
    if (!target_dlopen && libc_base) {
        target_dlopen = libc_base + get_offset("libc.so.6", "dlopen"); // Usually __libc_dlopen_mode
        if (!target_dlopen) target_dlopen = libc_base + get_offset("libc.so.6", "__libc_dlopen_mode");
    }

    if (!target_dlopen) {
        fprintf(stderr, "[-] Could not resolve dlopen in target.\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        exit(EXIT_FAILURE);
    }
    
    printf("[*] Resolved dlopen at: %lx\n", target_dlopen);

    // 4. Write Library Path to Stack
    size_t len = strlen(lib_path) + 1;
    // Align stack (keep 16-byte alignment logic for x86_64)
    regs.rsp -= (len + 15) & ~15; 
    unsigned long str_addr = regs.rsp;

    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, lib_path + i, (len - i < sizeof(long)) ? len - i : sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, str_addr + i, word) < 0) {
             perror("[-] Failed to write path");
        }
    }

    // 5. Setup Function Call (System V AMD64 ABI)
    // RDI = First Argument (Path String)
    // RSI = Second Argument (Flags: RTLD_NOW = 2)
    regs.rdi = str_addr;
    regs.rsi = 2; // RTLD_NOW
    regs.rip = target_dlopen;

    // Set return address to 0 (causes SIGSEGV on return, which we catch)
    regs.rsp -= 8;
    ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // 6. Wait for the crash (return from dlopen)
    waitpid(pid, &status, 0);
    
    // Check if it was SIGSEGV (expected) or something else
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
        printf("[+] Injection successful (caught expected return signal).\n");
    } else {
        printf("[!] Process stopped with unexpected signal: %d. Injection might have failed.\n", WSTOPSIG(status));
    }

    // 7. Restore and Detach
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

// --- Patching Logic (Optimized) ---

void patch(pid_t pid) {
    printf("[*] Starting smart patch scanner...\n");
    
    unsigned char pattern[] = "Java_com_roblox_protocols_localstor";
    size_t p_len = sizeof(pattern) - 1;
    
    char maps_path[64], line[512];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return;

    unsigned char *buf = NULL;
    size_t buf_cap = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;

        // Optimization: Only scan readable regions.
        // If we are looking for a string, it's likely in 'r--' or 'rw-'
        if (perms[0] != 'r') continue;

        size_t size = end - start;
        if (size == 0) continue;

        if (size > buf_cap) {
            buf = realloc(buf, size);
            buf_cap = size;
        }

        struct iovec local = {buf, size};
        struct iovec remote = {(void*)start, size};

        // Read the memory region
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) > 0) {
            for (size_t i = 0; i <= size - p_len; i++) {
                if (memcmp(buf + i, pattern, p_len) == 0) {
                    // MAGIC FORMULA from original code: (found_addr) - 0x1000d
                    unsigned long match_addr = start + i;
                    unsigned long patch_target = match_addr - 0x1000d;
                    
                    printf("[+] Pattern found at %lx. Patching target %lx\n", match_addr, patch_target);
                    
                    unsigned char patch_bytes[] = {0x90, 0x90}; // NOP NOP
                    struct iovec pl = {patch_bytes, 2};
                    struct iovec pr = {(void*)patch_target, 2};
                    
                    if (process_vm_writev(pid, &pl, 1, &pr, 1, 0) == 2) {
                        printf("[+] Patch Applied Successfully!\n");
                    } else {
                        perror("[-] Patch Write Failed");
                    }
                    
                    free(buf);
                    fclose(f);
                    return;
                }
            }
        }
    }

    printf("[-] Pattern not found in memory.\n");
    free(buf);
    fclose(f);
}

// --- Main ---

int main(int argc, char **argv) {
    // Expected args from GTK: ./injector [PID] [SO_PATH]
    // Or manual usage: ./injector [SO_PATH] (auto-find pid)
    
    pid_t pid = -1;
    char *so_path = NULL;

    if (argc >= 3) {
        // Mode 1: Provided by GTK
        pid = atoi(argv[1]);
        so_path = argv[2];
    } else if (argc == 2) {
        // Mode 2: Manual
        so_path = argv[1];
        pid = find_pid("sober");
    } else {
        // Fallback
        so_path = "./atingle.so";
        pid = find_pid("sober");
    }

    if (pid <= 0) {
        fprintf(stderr, "[-] Target process 'sober' not found or invalid PID.\n");
        return EXIT_FAILURE;
    }

    // Resolve absolute path for the .so (dlopen fails with relative paths sometimes)
    char real_so_path[PATH_MAX];
    if (!realpath(so_path, real_so_path)) {
        // If file doesn't exist, warn but try anyway if it's just a name
        strncpy(real_so_path, so_path, PATH_MAX);
    }

    inject(pid, real_so_path);
    patch(pid);

    return EXIT_SUCCESS;
}
