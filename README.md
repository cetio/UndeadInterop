# UndeadInterop

[![License](https://img.shields.io/badge/License-Apache--2.0-blue)](LICENSE.txt)

> [!CAUTION]
>
> I don't really care what you do with this project, but please don't use it to be nefarious. Even if you do, it is not an effective way to avoid detection by any modern antivirus or anticheat, so you'd be pretty silly.

UndeadInterop is a C# library for reading PE and module data from a running process, primarily its own, to resolve `ntdll.dll`/`win32u.dll` syscall IDs and invoke them directly. It also inspects usermode functions for hooks, covering inline jumps and calls, stack pivots, debug interrupts, and forwarded exports.

It started after reading secret.club's writeup on BattlEye's usermode API hooks and grew into a hook detection tool and PInvoke-style syscall wrapper. It was originally the backend for UndeadHotkeys, a frontend for designing macros that never went public and no longer has any surviving source.

## Features

- **Export walking** - Parses the PE export directory of a loaded module to enumerate `Nt*`/`Zw*` functions without relying on static offsets
- **Syscall resolution** - Derives syscall IDs from export order, falling back to forwarded addresses when present
- **Direct syscalls** - Generates small shellcode stubs at runtime and marshals them to typed delegates, so syscalls can be called like normal .NET methods
- **Hook detection** - Disassembles a function's prologue with Iced and classifies the control flow into `HookType.InlineJmp`, `InlineCall`, `InlineWarp`, `DebugInt`, `DebugPrk`, or `Forwarded`
- **Shared export handling** - Tracks `Nt`/`Zw` pairs so identifiers stay consistent with the real syscall table

## Usage

Define a delegate matching the syscall signature and attribute it with `NtImport`:

```csharp
[NtImport]
public delegate int NtSuspendProcess(nint handle);

var suspendProcess = NtApi.PrepCall<NtSuspendProcess>();
suspendProcess(processHandle);
```

If the delegate name doesn't match the export name, pass the real entry point:

```csharp
[NtImport("NtProtectVirtualMemory")]
public delegate int ProtectMemory(nint handle, ref nint baseAddress, ref nint size, uint newProtect, out uint oldProtect);
```

For cases where a compile-time delegate isn't available, resolve one dynamically:

```csharp
dynamic call = NtApi.PrepDynamic("NtClose", typeof(int), typeof(nint));
call(handle);
```

Check whether any `ntdll`/`win32u` export in the current process is hooked:

```csharp
if (NtApi.IsUserApiHooked())
{
    // at least one Nt/Zw export has inline, stack, debug, or forwarding hooks
}
```

## Architecture

- `NtApi.cs` - Export enumeration, syscall ID resolution, shellcode generation, and delegate caching
- `NtImport.cs` - Attribute used to mark a delegate as a syscall import
- `NtStatus.cs` - NTSTATUS values returned by native calls
- `Meta/ExportData.cs`/`Meta/ExportFunction.cs` - Raw PE export directory data and per-function records
- `Meta/FunctionAnalyzer.cs`/`Meta/FunctionBlock.cs` - Disassembles a function's code region into instruction blocks for analysis
- `Meta/Hooking/HookAnalyzer.cs`/`Meta/Hooking/HookType.cs` - Classifies hook types from the disassembled instructions

Targets `net6.0`, Windows only, x64 (the generated syscall stub is x86_64 only), and depends on [Iced](https://github.com/icedland/iced) for disassembly.

## License

UndeadInterop is licensed under [Apache-2.0](LICENSE.txt).
