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

#include "nerror.h"
#include "ntosutils.h"
#include "ntmem.h"
#include "ntosutilswin.h"

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	if (argc < 3) {
#ifdef LOG_LEVEL_1
		LOG_INFO(
			"Usage: %s <thread_id:DWORD or process_id:DWORD> <dll_path:string>",
			argv[0]);
#endif /* ifdef LOG_LEVEL_1 */

		return 0x10;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("Neptune initilaized!");
#endif /* ifdef LOG_LEVEL_1 */

	const char *dll_path = argv[2];
	const char *id_str = argv[1];

#ifdef LOG_LEVEL_1
	LOG_INFO("DLL Path(%s)", dll_path);
#endif /* ifdef LOG_LEVEL_1 */

	DWORD id = atoi(id_str);

	if (id < 0) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Invalid id: must be greater than 0");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x11;
	}

	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetModuleHandleA failed");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x20;
	}

	void *load_library_func = GetProcAddress(kernel32, "LoadLibraryA");
	if (load_library_func == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetProcAddress failed");
#endif /* ifdef LOG_LEVEL_1 */

		return 0x21;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("LoadLibraryA=%p", load_library_func);
#endif /* ifdef LOG_LEVEL_1 */

	// Initialize the ntutils layer for working on the target thread.
	if (HAS_ERR(nosu_attach(id))) {
#ifdef LOG_LEVEL_1
		LOG_WARN("nosu_attach failed");
#endif /* ifdef LOG_LEVEL_1 */

		if (HAS_ERR(nosu_find_thread_and_upgrade(id))) {
#ifdef LOG_LEVEL_1
			LOG_ERROR("nosu_find_thread_and_upgrade failed");
#endif /* ifdef LOG_LEVEL_1 */

			neptune_destroy();
			return 0x06;
		}
	}

	size_t dll_path_len = strlen(dll_path);
	size_t dll_path_size = dll_path_len + 1;

	ntmem_t *ntmem = ntm_create_with_alloc_ex(dll_path_size + 1);
	if (ntmem == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("ntm_create failed");
#endif /* ifdef LOG_LEVEL_1 */

		ntu_destroy();
		neptune_destroy();
		return 0x92;
	}

	// Copy the converted string into memory that will be pushed to the target.
	void *local = NTM_LOCAL(ntmem);
	memcpy(local, dll_path, dll_path_size);

	// Push the DLL path into the remote memory.
	void *dll_path_addr = ntm_push(ntmem);
	if (dll_path_addr == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("ntm_push failed");
#endif /* ifdef LOG_LEVEL_1 */

		ntu_destroy();
		neptune_destroy();
		return 0x93;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif /* ifdef LOG_LEVEL_1 */

	// Call LoadLibraryA inside the target thread context.
	void *load_library_ret = ntu_ucall(load_library_func, dll_path_addr);

#ifdef LOG_LEVEL_1
	LOG_INFO("Return Value(%p)", load_library_ret);
#endif /* ifdef LOG_LEVEL_1 */

	ntm_delete(ntmem);

	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}
