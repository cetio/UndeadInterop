using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using UndeadInterop.Meta;
using UndeadInterop.Meta.Hooking;

namespace UndeadInterop
{
    public class NtApi
    {
        [DllImport("kernel32.dll")]
        private static extern uint VirtualAlloc(nint lpStartAddr, int size, uint flAllocationType, uint flProtect);

        private static readonly Func<Type[], Type> CreateDynamicDelegate = (Func<Type[], Type>)Delegate.CreateDelegate(typeof(Func<Type[], Type>),
            typeof(Expression).Assembly.GetType("System.Linq.Expressions.Compiler.DelegateHelpers")!
            .GetMethod("MakeNewCustomDelegate", BindingFlags.NonPublic | BindingFlags.Static)!);

        private static List<ExportFunction> _functionCache = new List<ExportFunction>();
        private static Dictionary<Type, Delegate> _delegateCache = new Dictionary<Type, Delegate>();
        private static Dictionary<string, Type> _dynamicsCache = new Dictionary<string, Type>();

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
            ExportFunction function = GetFunctions().Where(x => x.Name == (import.Entrypoint ?? typeof(T).Name)).FirstOrDefault();

            return (T)PrepCall_Explicit(import.Entrypoint ?? typeof(T).Name, typeof(T));
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
            string key = name + returnType.Name + string.Join(", ", (object[])parameterTypes);

            if (!_dynamicsCache.ContainsKey(key))
            {
                Type[] args = new Type[parameterTypes.Length + 1];
                Array.Copy(parameterTypes, args, parameterTypes.Length);
                args[^1] = returnType;

                _dynamicsCache.Add(key, CreateDynamicDelegate(args));
            }

            return PrepCall_Explicit(name, _dynamicsCache[key]);
        }

        private static dynamic PrepCall_Explicit(string name, Type type)
        {
            if (!_delegateCache.ContainsKey(type))
            {
                byte[] shellcode = GenerateShellcode(name);
                nint shellcodeAddress = Marshal.UnsafeAddrOfPinnedArrayElement(shellcode, 0);

                VirtualAlloc(shellcodeAddress, 14, 0x1000, 0x40);

                Delegate @delegate = Marshal.GetDelegateForFunctionPointer(shellcodeAddress, type);
                _delegateCache.Add(type, @delegate);
            }

            return _delegateCache[type];
        }

        public static bool IsUserApiHooked()
        {
            return GetFunctions().Count(x => x.GetHookType() != HookType.NONE) != 0;
        }

        private static unsafe int GetIdentifier(string name)
        {
            ExportFunction function = GetFunctions().Where(x => x.Name == name).FirstOrDefault();

            if (function.Address == (byte*)0)
                throw new ArgumentException($"{name} is not an export function");

            return function.GetHookType() == HookType.FORWARDED
                ? *(int*)(function.Address + sizeof(int))
                : (function.IsSharedExport ? 0 : 4072) + _functionCache.IndexOf(function); /* may be inconsistent across versions? i hope not */
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
                var exportData = GetExportData(module);

                for (var i = 0; i < exportData.NumberOfNames; i++)
                {
                    ExportFunction function = BuildFunction(module, exportData.OrdinalBase, exportData.FunctionsRva,
                        exportData.NamesRva, exportData.OrdinalsRva, i);

                    if (function.Name is null)
                        continue;

                    if (function.Name.StartsWith("Zw"))
                    {
                        var sharedIndex = _functionCache.IndexOf(_functionCache.Where(x => x.Name == "Nt" + function.Name.Remove(0, 2)).First());
                        var sharedExport = _functionCache[sharedIndex];
                        sharedExport.IsSharedExport = true;

                        _functionCache[sharedIndex] = sharedExport;
                        continue;
                    }

                    _functionCache.Add(function);
                }
            }

            _functionCache = _functionCache.OrderBy(x => (nint)x.Address).ToList();
            return _functionCache;
        }

        private static ExportData GetExportData(ProcessModule module)
        {
            var peHeader = Marshal.ReadInt32(module.BaseAddress + 0x3C);
            var optHeader = module.BaseAddress + peHeader + 0x18;
            var magic = Marshal.ReadInt16(optHeader);
            var pExport = magic == 0x010b ? optHeader + 0x60 : optHeader + 0x70;
            var exportRva = Marshal.ReadInt32(pExport);
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
                OrdinalsRva = ordinalsRva
            };
        }

        private static unsafe ExportFunction BuildFunction(ProcessModule module, int ordinalBase, int functionsRva, int namesRva, int ordinalsRva, int index)
        {
            var functionOrdinal = Marshal.ReadInt16(module.BaseAddress + ordinalsRva + index * 2) + ordinalBase;
            var functionRva = Marshal.ReadInt32(module.BaseAddress + functionsRva + 4 * (functionOrdinal - ordinalBase));
            var functionAddr = (byte*)module.BaseAddress + functionRva;
            var functionName = Marshal.PtrToStringAnsi(module.BaseAddress + Marshal.ReadInt32(module.BaseAddress + namesRva + index * 4));

            if (!string.IsNullOrWhiteSpace(functionName) &&
                (functionName.StartsWith("Nt") || functionName.StartsWith("Zw")) &&
                char.IsUpper(functionName[2]))
            {
                return new ExportFunction(functionName, functionAddr, module);
            }

            return new ExportFunction(null, (byte*)0, module);
        }

        private static byte[] GenerateShellcode(string name)
        {
            byte[] shellcode = GC.AllocateArray<byte>(14, true);
            int id = GetIdentifier(name);

            // mov r10, rcx
            shellcode[0] = 0x4c;
            shellcode[1] = 0x8b;
            shellcode[2] = 0xd1;

            // mov eax, id
            shellcode[3] = 0xb8;
            shellcode[4] = (byte)(id >> 0);  // byte 1
            shellcode[5] = (byte)(id >> 8);  // byte 2
            shellcode[6] = (byte)(id >> 16); // byte 3
            shellcode[7] = (byte)(id >> 32); // byte 4

            // syscall eax
            shellcode[8] = 0x0f;
            shellcode[9] = 0x05;

            // ret
            shellcode[10] = 0xc3;

            return shellcode;
        }
    }
}
