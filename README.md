# GhostInjector

**GhostInjector** is a stealthy DLL injector that avoids traditional APIs like `OpenProcess`, `CreateRemoteThread`, or `WriteProcessMemory`. Instead, it uses thread hijacking combined with pre-existing gadgets in the target process to call `LoadLibraryA`. Powered by the [woldann/NThread](https://github.com/woldann/NThread) library.

## Features

- ❌ No `OpenProcess`
- ❌ No `CreateRemoteThread`
- ✅ Thread hijacking with `LoadLibraryA` call
- ✅ Uses existing remote gadgets (e.g., `malloc`, `memset`, `fread`)
- ✅ Injects DLL path using target’s own memory management functions
- ✅ Highly stealthy — avoids common injection detection vectors

## How It Works

1. Identifies a thread in the target process (either specified directly or found by scanning).
2. Finds the address of `LoadLibraryA` within the remote process.
3. Allocates memory for the DLL path using `msvcrt.dll!malloc` inside the target.
4. Writes the DLL path using existing functions like `memset` or `fread`.
5. Hijacks the target thread to call `LoadLibraryA` with the injected DLL path.
6. If a thread ID is provided, it attempts direct hijack. If it's a process ID, it enumerates threads and selects the first responsive one.

## Usage

```bash
ghostinjector.exe <thread_id:DWORD or process_id:DWORD> <dll_path:string>
```

