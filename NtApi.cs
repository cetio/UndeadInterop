using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using Iced.Intel;
using UndeadInterop.Meta;
using UndeadInterop.Meta.Hooking;
using static Iced.Intel.AssemblerRegisters;

namespace UndeadInterop;

public class NtApi
{
    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(nint lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint LoadLibraryEx(string lpLibFileName, nint hFile, uint dwFlags);

    private const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20;

    private static readonly Func<Type[], Type> CreateDynamicDelegate = (Func<Type[], Type>)Delegate.CreateDelegate(typeof(Func<Type[], Type>),
        typeof(Expression).Assembly.GetType("System.Linq.Expressions.Compiler.DelegateHelpers")!
        .GetMethod("MakeNewCustomDelegate", BindingFlags.NonPublic | BindingFlags.Static)!);

    public static bool UseCloneForSyscalls { get; set; }
    public static bool UseCloneForHooks { get; set; }
    public static string? ClonePath { get; set; }

    private static List<ExportFunction> _functionCache = new();
    private static List<ExportFunction> _cloneFunctionCache = new();
    private static Dictionary<string, ModuleMap> _cloneCache = new();
    private static Dictionary<Type, Delegate> _delegateCache = new();
    private static Dictionary<string, Type> _dynamicsCache = new();

    /// <summary>
    /// Prepares the syscall associated with a compile-time delegate.
    /// </summary>
    /// <returns>The delegate to execute the syscall associated with the provided compile-time delegate.</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public static T PrepCall<T>() where T : Delegate
    {
        NtImport import = typeof(T).GetCustomAttribute<NtImport>()
                ?? throw new ArgumentException("The provided delegate was not attributed with NtImport");
        return (T)PrepCallExplicit(import.Entrypoint ?? typeof(T).Name, typeof(T));
    }

    /// <summary>
    /// Prepares the syscall associated with the given name, types are not dynamically resolved.
    /// </summary>
    /// <param name="name">The name name of the function to find.</param>
    /// <param name="returnType">The return type of the function associated with the name.</param>
    /// <param name="parameterTypes">The parameter types of the function associated with the name.</param>
    /// <returns>The delegate to execute the syscall associated with the provided name name.</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public static dynamic PrepDynamic(string name, Type returnType, params Type[] parameterTypes)
    {
        string key = name + returnType.FullName + string.Join(", ", parameterTypes.Select(t => t.FullName));

        if (!_dynamicsCache.ContainsKey(key))
        {
            Type[] args = new Type[parameterTypes.Length + 1];
            Array.Copy(parameterTypes, args, parameterTypes.Length);
            args[^1] = returnType;

            _dynamicsCache.Add(key, CreateDynamicDelegate(args));
        }

        return PrepCallExplicit(name, _dynamicsCache[key]);
    }

    private static dynamic PrepCallExplicit(string name, Type type)
    {
        if (!_delegateCache.ContainsKey(type))
        {
            byte[] shellcode = GenerateShellcode(name);
            nint shellcodeAddress = Marshal.UnsafeAddrOfPinnedArrayElement(shellcode, 0);

            if (!VirtualProtect(shellcodeAddress, shellcode.Length, 0x40, out _))
                throw new InvalidOperationException("Failed to mark shellcode memory as executable");

            Delegate @delegate = Marshal.GetDelegateForFunctionPointer(shellcodeAddress, type);
            _delegateCache.Add(type, @delegate);
        }

        return _delegateCache[type];
    }

    public static bool IsUserApiHooked()
    {
        var cloneFunctions = UseCloneForHooks ? GetCloneFunctions() : null;
        return GetFunctions().Count(x =>
        {
            var cloneFunc = cloneFunctions?.FirstOrDefault(c => c.Name == x.Name);
            return x.GetHookType(cloneFunc) != HookType.None;
        }) != 0;
    }

    private static unsafe int GetIdentifier(string name)
    {
        var cache = UseCloneForSyscalls ? GetCloneFunctions() : GetFunctions();
        ExportFunction function = cache.Where(x => x.Name == name).FirstOrDefault();

        if (function.Address == (byte*)0)
            throw new ArgumentException($"{name} is not an export function");

        return function.GetHookType() == HookType.Forwarded
            ? *(int*)(function.Address + sizeof(int))
            : (function.IsSharedExport ? 0 : 4072) + cache.IndexOf(function); /* may be inconsistent across versions? i hope not */
    }

    private static unsafe List<ExportFunction> GetFunctions()
    {
        if (_functionCache.Count != 0)
            return _functionCache;

        ProcessModule[] modules = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
            .Where(x => x.ModuleName is "ntdll.dll" or "win32u.dll")
            .ToArray();

        foreach (ProcessModule module in modules)
        {
            var moduleMap = new ModuleMap(module.BaseAddress, module.ModuleMemorySize, module.ModuleName);
            PopulateFunctions(moduleMap, _functionCache);
        }

        _functionCache = _functionCache.OrderBy(x => (nint)x.Address).ToList();
        return _functionCache;
    }

    private static unsafe List<ExportFunction> GetCloneFunctions()
    {
        if (_cloneFunctionCache.Count != 0)
            return _cloneFunctionCache;

        string[] moduleNames = { "ntdll.dll", "win32u.dll" };

        foreach (var moduleName in moduleNames)
        {
            if (!_cloneCache.TryGetValue(moduleName, out var cloneMap))
            {
                cloneMap = LoadClone(moduleName);
                _cloneCache[moduleName] = cloneMap;
            }

            PopulateFunctions(cloneMap, _cloneFunctionCache);
        }

        _cloneFunctionCache = _cloneFunctionCache.OrderBy(x => (nint)x.Address).ToList();
        return _cloneFunctionCache;
    }

    private static ModuleMap LoadClone(string moduleName)
    {
        string path = Path.Combine(ClonePath ?? Environment.SystemDirectory, moduleName);
        nint hModule = LoadLibraryEx(path, nint.Zero, LOAD_LIBRARY_AS_IMAGE_RESOURCE);

        if (hModule == nint.Zero)
            throw new InvalidOperationException($"Failed to load clone of {moduleName}");

        nint baseAddress = hModule & ~(nint)1;
        int peHeader = Marshal.ReadInt32(baseAddress + 0x3C);
        nint optHeader = baseAddress + peHeader + 0x18;
        int sizeOfImage = Marshal.ReadInt32(optHeader + 0x38);

        return new ModuleMap(baseAddress, sizeOfImage, moduleName);
    }

    private static unsafe void PopulateFunctions(ModuleMap module, List<ExportFunction> cache)
    {
        var exportData = GetExportData(module);

        for (var i = 0; i < exportData.NumberOfNames; i++)
        {
            ExportFunction function = BuildFunction(module, exportData.OrdinalBase, exportData.FunctionsRva,
                exportData.NamesRva, exportData.OrdinalsRva, i, exportData.ExportRva, exportData.ExportSize);

            if (function.Name is null)
                continue;

            if (function.Name.StartsWith("Zw"))
            {
                var ntName = "Nt" + function.Name.Remove(0, 2);
                var ntFunction = cache.FirstOrDefault(x => x.Name == ntName);
                if (ntFunction.Name is not null)
                {
                    var sharedIndex = cache.IndexOf(ntFunction);
                    var sharedExport = cache[sharedIndex];
                    sharedExport.IsSharedExport = true;

                    cache[sharedIndex] = sharedExport;
                }
                continue;
            }

            cache.Add(function);
        }
    }

    private static ExportData GetExportData(ModuleMap module)
    {
        var peHeader = Marshal.ReadInt32(module.BaseAddress + 0x3C);
        var optHeader = module.BaseAddress + peHeader + 0x18;
        var magic = Marshal.ReadInt16(optHeader);
        var pExport = magic == 0x010b ? optHeader + 0x60 : optHeader + 0x70;
        var exportRva = Marshal.ReadInt32(pExport);
        var exportSize = Marshal.ReadInt32(pExport + 4);
        var ordinalBase = Marshal.ReadInt32(module.BaseAddress + exportRva + 0x10);
        var numberOfNames = Marshal.ReadInt32(module.BaseAddress + exportRva + 0x18);
        var functionsRva = Marshal.ReadInt32(module.BaseAddress + exportRva + 0x1C);
        var namesRva = Marshal.ReadInt32(module.BaseAddress + exportRva + 0x20);
        var ordinalsRva = Marshal.ReadInt32(module.BaseAddress + exportRva + 0x24);

        return new ExportData
        {
            OrdinalBase = ordinalBase,
            NumberOfNames = numberOfNames,
            FunctionsRva = functionsRva,
            NamesRva = namesRva,
            OrdinalsRva = ordinalsRva,
            ExportRva = exportRva,
            ExportSize = exportSize
        };
    }

    private static unsafe ExportFunction BuildFunction(ModuleMap module, int ordinalBase, int functionsRva, int namesRva, int ordinalsRva, int index, int exportDirRva, int exportDirSize)
    {
        var functionOrdinal = Marshal.ReadInt16(module.BaseAddress + ordinalsRva + index * 2) + ordinalBase;
        var functionRva = Marshal.ReadInt32(module.BaseAddress + functionsRva + 4 * (functionOrdinal - ordinalBase));
        var functionAddr = (byte*)module.BaseAddress + functionRva;
        var functionName = Marshal.PtrToStringAnsi(module.BaseAddress + Marshal.ReadInt32(module.BaseAddress + namesRva + index * 4));

        bool isForwarded = functionRva >= exportDirRva && functionRva < exportDirRva + exportDirSize;

        if (!string.IsNullOrWhiteSpace(functionName) &&
            (functionName.StartsWith("Nt") || functionName.StartsWith("Zw")) &&
            char.IsUpper(functionName[2]))
        {
            return new ExportFunction(functionName, functionAddr, module, isForwarded);
        }

        return new ExportFunction(null, (byte*)0, module);
    }

    private static byte[] GenerateShellcode(string name)
    {
        int id = GetIdentifier(name);

        var assembler = new Assembler(64);
        assembler.mov(r10, rcx);
        assembler.mov(eax, id);
        assembler.syscall();
        assembler.ret();

        using var stream = new MemoryStream();
        assembler.Assemble(new StreamCodeWriter(stream), 0);

        byte[] shellcode = GC.AllocateArray<byte>((int)stream.Length, true);
        stream.Position = 0;
        stream.Read(shellcode, 0, shellcode.Length);

        return shellcode;
    }
}
