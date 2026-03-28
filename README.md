
  ## disclaimer

  proof of concept for security research and educational purposes only.
  
  ## background
  
  .NET NativeAOT compiles C# code ahead-of-time into native PE binaries. unlike regular .NET assemblies, these can't be
  loaded with `Assembly.Load`. unlike regular native PEs, they can't be loaded with existing memory loaders
  (MemoryModule, Donut, sRDI, pe_to_shellcode) - all crash with `STATUS_FAIL_FAST_EXCEPTION` (0xc0000602).

  this has been an open problem since at least 2022. see [dotnet/runtime
  #77978](https://github.com/dotnet/runtime/discussions/77978). the dotnet team explicitly stated they would not make
  the runtime compatible with from-memory loaders.


  NativeAOT binaries carry their own runtime (GC, thread management, exception handling). during initialization, the
  runtime calls `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)` to locate itself in memory. on Windows
10+,
   this lookup uses an internal red-black tree (`BaseAddressIndex`) rather than the PEB linked lists. manually mapped
  modules aren't in this tree, so the lookup returns NULL and the runtime calls `__fastfail`.

  even after solving that, NativeAOT requires proper static TLS initialization through the OS loader's internal
  `LdrpHandleTlsData` function, and a complete `LDR_DATA_TABLE_ENTRY` with fields like `DdagNode` and
  `BaseAddressIndexNode` that most manual mapping implementations don't touch.

  ## how it works

  1. map PE sections into memory, apply relocations, resolve imports
  2. create a full `LDR_DATA_TABLE_ENTRY` (0x200 bytes) with all required fields including `DdagNode`, `HashLinks`,
  `BaseNameHashValue`, `OriginalBase`, `LoadReason`, `ReferenceCount`
  3. link into all three PEB loader lists
  4. find `LdrpModuleBaseAddressIndex` by walking parent pointers from a known module to the tree root, then scanning
  ntdll's `.data` section for the root pointer
  5. insert into the `BaseAddressIndex` red-black tree via `RtlRbInsertNodeEx`
  6. hook `GetModuleHandleExW` in the PE's IAT as a backup mechanism
  7. find `LdrpHandleTlsData` by scanning ntdll for a function that calls `RtlImageDirectoryEntryToData`,
  `RtlAcquireSRWLockExclusive`, `RtlAllocateHeap`, and `memcpy` simultaneously.
  8. call `LdrpHandleTlsData` to register TLS with the OS loader
  9. register exception handling tables via `RtlAddFunctionTable`
  10. set per-section memory protections
  11. call the entry point

  ## build

  cl.exe /O2 /EHsc nativeaot_loader.cpp

  ## usage

  nativeaot_loader.exe /path/to/nativeAOTapp.exe

  ## test payload

  cd payload
  dotnet publish -c Release -r win-x64

  requires .NET 8+ SDK.

  ## compatibility

  tested on Windows 11 24H2 (build 26100). should work on Windows 10 1903+ and all Windows 11 builds. x64 only. any
.NET
   7+ NativeAOT binary (`PublishAot=true`).

  the `LdrpHandleTlsData` scan is reference-based (matches call targets against known exports, uses `RUNTIME_FUNCTION`
  entries for boundaries) so it adapts across ntdll versions.

  ## references

  - [dotnet/runtime #77978](https://github.com/dotnet/runtime/discussions/77978) - the open problem
  - [dotnet/runtime - NativeAOT source](https://github.com/dotnet/runtime/tree/main/src/coreclr/nativeaot/Runtime) -
  `RhpReversePInvokeAttachOrTrapThread2`, `ThreadStore::AttachCurrentThread`, `PalGetModuleHandleFromPointer`
  - [Blackbone](https://github.com/DarthTon/Blackbone) - BaseAddressIndex tree insertion approach
  - [MemoryModulePP](https://github.com/bb107/MemoryModulePP) - TLS handling concepts

