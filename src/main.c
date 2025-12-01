/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software. 
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#include "nerror.h"
#include "ntosutils.h"
#include "ntmem.h"
#include "ntosutilswin.h"

/**
 * @brief Check if the given ID is a process ID
 * @param id The ID to check
 * @return true if it's a process ID, false if not (likely a thread ID)
 */
static bool is_process_id(uint32_t id)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };

	if (Process32First(snap, &pe)) {
		do {
			if (pe.th32ProcessID == id) {
				CloseHandle(snap);
				return true;
			}
		} while (Process32Next(snap, &pe));
	}

	CloseHandle(snap);
	return false;
}

/**
 * @brief Get the process ID that owns the given thread
 * @param thread_id The thread ID
 * @return Process ID, or 0 if not found
 */
static DWORD get_process_id_from_thread(DWORD thread_id)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te = { .dwSize = sizeof(te) };

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32ThreadID == thread_id) {
				DWORD pid = te.th32OwnerProcessID;
				CloseHandle(snap);
				return pid;
			}
		} while (Thread32Next(snap, &te));
	}

	CloseHandle(snap);
	return 0;
}

#ifdef LOG_LEVEL_3
/**
 * @brief Log all modules loaded in the target process
 * @param pid The process ID
 */
static void log_process_modules(DWORD pid)
{
	HANDLE snap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		LOG_WARN(
			"Failed to enumerate modules for process %u (error: %lu)",
			pid, GetLastError());
		return;
	}

	MODULEENTRY32 me = { .dwSize = sizeof(me) };
	int count = 0;

	LOG_INFO("=== Modules loaded in process %u ===", pid);

	if (Module32First(snap, &me)) {
		do {
			LOG_INFO("  [%d] %s (base: %p, size: %u)", ++count,
				 me.szModule, me.modBaseAddr, me.modBaseSize);
		} while (Module32Next(snap, &me));
	}

	LOG_INFO("=== Total: %d modules ===", count);
	CloseHandle(snap);
}
#endif

void print_usage()
{
	printf("GhostInjector - DLL Injection tool for Windows processes\n\n");
	printf("Examples:\n");
	printf("  ghostinjector.exe 1234 mydll.dll\n");
	printf("  ghostinjector.exe 5678 first.dll second.dll third.dll\n\n");
	printf("Usage:\n");
	printf("  ghostinjector.exe <process_id> <dll_path> [dll_path2 ...]\n");
	printf("  ghostinjector.exe -h | --help\n");
}

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	if (argc < 3 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		print_usage();
		neptune_destroy();
		return EXIT_SUCCESS;
	}

	uint32_t id = atoi(argv[1]);

#ifdef LOG_LEVEL_1
	LOG_INFO("Neptune initialized!");
	LOG_INFO("Number of DLLs to inject: %d", argc - 2);
#endif

	if (id == 0) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Invalid id: must be greater than 0");
#endif
		neptune_destroy();
		return 0x11;
	}

	bool is_process = is_process_id(id);
	DWORD pid;

	if (is_process) {
		pid = id;
#ifdef LOG_LEVEL_2
		LOG_INFO("ID %u is a process", id);
#endif
	} else {
		pid = get_process_id_from_thread(id);
#ifdef LOG_LEVEL_2
		LOG_INFO("ID %u is a thread, owner process ID: %u", id, pid);
#endif
		if (pid == 0) {
#ifdef LOG_LEVEL_1
			LOG_ERROR("Failed to get process ID from thread %u",
				  id);
#endif
			neptune_destroy();
			return 0x08;
		}
	}

	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetModuleHandleA failed");
#endif
		neptune_destroy();
		return 0x20;
	}

	FARPROC load_library_func = GetProcAddress(kernel32, "LoadLibraryA");
	if (load_library_func == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetProcAddress failed");
#endif
		neptune_destroy();
		return 0x21;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("LoadLibraryA=%p", (void *)load_library_func);
#endif

#ifdef LOG_LEVEL_3
	log_process_modules(pid);
#endif

	if (is_process) {
		if (HAS_ERR(nosu_find_thread_and_upgrade(id))) {
#ifdef LOG_LEVEL_1
			LOG_ERROR(
				"nosu_find_thread_and_upgrade failed for thread %u",
				id);
#endif
			neptune_destroy();
			return 0x07;
		}
	} else {
		if (HAS_ERR(nosu_attach(id))) {
#ifdef LOG_LEVEL_1
			LOG_ERROR("nosu_attach failed for process %u", id);
#endif
			neptune_destroy();
			return 0x06;
		}
	}

	for (int i = 2; i < argc; i++) {
		const char *dll_path = argv[i];

#ifdef LOG_LEVEL_1
		LOG_INFO("Injecting DLL [%d/%d]: %s", i - 1, argc - 2,
			 dll_path);
#endif

		size_t dll_path_len = strlen(dll_path);
		size_t dll_path_size = dll_path_len + 1;

		ntmem_t *ntmem = ntm_create_with_alloc_ex(dll_path_size + 1);
		if (ntmem == NULL) {
#ifdef LOG_LEVEL_1
			LOG_ERROR("ntm_create failed for %s", dll_path);
#endif
			continue;
		}

		void *local = NTM_LOCAL(ntmem);
		memcpy(local, dll_path, dll_path_size);

		void *dll_path_addr = ntm_push(ntmem);
		if (dll_path_addr == NULL) {
#ifdef LOG_LEVEL_1
			LOG_ERROR("ntm_push failed for %s", dll_path);
#endif
			ntm_delete(ntmem);
			continue;
		}

#ifdef LOG_LEVEL_1
		LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif

		void *load_library_ret =
			ntu_ucall((void *)load_library_func, dll_path_addr);

#ifdef LOG_LEVEL_1
		LOG_INFO("LoadLibrary returned: %p", load_library_ret);
		if (load_library_ret != NULL) {
			LOG_INFO("Successfully injected: %s", dll_path);
		} else {
			LOG_ERROR("Failed to inject: %s", dll_path);
		}
#endif

		ntm_delete(ntmem);
	}
	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}