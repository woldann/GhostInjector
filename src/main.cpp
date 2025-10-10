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

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <cxxopts.hpp>
#include <windows.h>

extern "C" {
#include "nerror.h"
#include "ntosutils.h"
#include "ntmem.h"
#include "ntosutilswin.h"
}

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	// Parse command line arguments with cxxopts
	cxxopts::Options options("GhostInjector", 
	                         "DLL Injection tool for Windows processes\n\n"
	                         "Examples:\n"
	                         "  ghostinjector.exe 1234 mydll.dll\n"
	                         "  ghostinjector.exe 5678 first.dll second.dll third.dll");
	
	options.add_options()
		("h,help", "Print this help message")
		("positional", "Process ID and DLL path(s)", 
		 cxxopts::value<std::vector<std::string>>());

	options.parse_positional({"positional"});
	options.positional_help("<process_id> <dll_path> [dll_path2 ...]");
	options.custom_help("[OPTIONS] <process_id> <dll_path> [dll_path2 ...]");

	try {
		auto result = options.parse(argc, argv);

		// Show help if no arguments or --help flag
		if (argc == 1 || result.count("help")) {
#ifdef LOG_LEVEL_1
			LOG_INFO("%s", options.help().c_str());
#else
			std::cout << options.help() << std::endl;
#endif
			neptune_destroy();
			return EXIT_SUCCESS;
		}

		if (!result.count("positional")) {
			std::cerr << "Error: Missing required arguments" << std::endl;
			std::cerr << std::endl << options.help() << std::endl;
			neptune_destroy();
			return 0x10;
		}

		auto& positional = result["positional"].as<std::vector<std::string>>();
		
		if (positional.size() < 2) {
			std::cerr << "Error: Not enough arguments (need at least PID and one DLL path)" << std::endl;
			std::cerr << std::endl << options.help() << std::endl;
			neptune_destroy();
			return 0x10;
		}

		uint32_t id = std::stoul(positional[0]);

#ifdef LOG_LEVEL_1
		LOG_INFO("Neptune initialized!");
		LOG_INFO("ID: %u", id);
		LOG_INFO("Number of DLLs to inject: %zu", positional.size() - 1);
#endif

	if (id == 0) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Invalid id: must be greater than 0");
#endif
		neptune_destroy();
		return 0x11;
	}

	// Get kernel32.dll handle (outside of any block for proper scope)
	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetModuleHandleA failed");
#endif
		neptune_destroy();
		return 0x20;
	}

	// Get LoadLibraryA function address (outside of any block for proper scope)
	FARPROC load_library_func = GetProcAddress(kernel32, "LoadLibraryA");
	if (load_library_func == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetProcAddress failed");
#endif
		neptune_destroy();
		return 0x21;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("LoadLibraryA=%p", (void*)load_library_func);
#endif

		// Initialize the ntutils layer for working on the target thread.
		if (HAS_ERR(nosu_attach(id))) {
#ifdef LOG_LEVEL_1
			LOG_WARN("nosu_attach failed");
#endif

			if (HAS_ERR(nosu_find_thread_and_upgrade(id))) {
#ifdef LOG_LEVEL_1
				LOG_ERROR("nosu_find_thread_and_upgrade failed");
#endif
				neptune_destroy();
				return 0x06;
			}
		}

		// Process all DLL paths starting from index 1
		for (size_t i = 1; i < positional.size(); i++) {
			const char *dll_path = positional[i].c_str();

#ifdef LOG_LEVEL_1
			LOG_INFO("Injecting DLL [%zu/%zu]: %s", i, positional.size() - 1, dll_path);
#endif

			size_t dll_path_len = strlen(dll_path);
			size_t dll_path_size = dll_path_len + 1;

			ntmem_t *ntmem = ntm_create_with_alloc_ex(dll_path_size + 1);
			if (ntmem == NULL) {
#ifdef LOG_LEVEL_1
				LOG_ERROR("ntm_create failed for %s", dll_path);
#endif
				continue; // Try next DLL
			}

			// Copy the converted string into memory that will be pushed to the target.
			void *local = NTM_LOCAL(ntmem);
			memcpy(local, dll_path, dll_path_size);

			// Push the DLL path into the remote memory.
			void *dll_path_addr = ntm_push(ntmem);
			if (dll_path_addr == NULL) {
#ifdef LOG_LEVEL_1
				LOG_ERROR("ntm_push failed for %s", dll_path);
#endif
				ntm_delete(ntmem);
				continue; // Try next DLL
			}

#ifdef LOG_LEVEL_1
			LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif

			// Call LoadLibraryA inside the target thread context.
			void *load_library_ret = ntu_ucall((void*)load_library_func, dll_path_addr);

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

	} catch (const cxxopts::exceptions::exception& e) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Error parsing arguments: %s", e.what());
#else
		std::cerr << "Error parsing arguments: " << e.what() << std::endl;
#endif
		neptune_destroy();
		return 0x10;
	}
}
