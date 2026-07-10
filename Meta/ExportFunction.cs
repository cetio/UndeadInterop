namespace UndeadInterop.Meta;

internal unsafe struct ExportFunction
{
    public readonly string? Name { get; }
    internal readonly byte* Address { get; }
    internal readonly ModuleMap Module { get; }
    public bool IsSharedExport { get; set; }
    public bool IsForwardedExport { get; }

    public ExportFunction(string? name, byte* address, ModuleMap module, bool isForwardedExport = false)
    {
        Name = name;
        Address = address;
        Module = module;
        IsSharedExport = false;
        IsForwardedExport = isForwardedExport;
    }
}
