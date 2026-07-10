namespace UndeadInterop.Meta;

internal struct ModuleMap
{
    public readonly nint BaseAddress;
    public readonly int ModuleMemorySize;
    public readonly string ModuleName;

    public ModuleMap(nint baseAddress, int moduleMemorySize, string moduleName)
    {
        BaseAddress = baseAddress;
        ModuleMemorySize = moduleMemorySize;
        ModuleName = moduleName;
    }
}
