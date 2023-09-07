using System.Diagnostics;

namespace UndeadInterop.Meta
{
    internal unsafe struct ExportFunction
    {
        public readonly string Name { get; }
        internal readonly byte* Address { get; }
        internal readonly ProcessModule Module { get; }
        public bool IsSharedExport { get; set; }

        public ExportFunction(string name, byte* address, ProcessModule module)
        {
            Name = name;
            Address = address;
            Module = module;
            IsSharedExport = false;
        }
    }
}
