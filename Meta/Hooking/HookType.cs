namespace UndeadInterop.Meta.Hooking
{
    public enum HookType
    {
        None,
        InlineJmp,
        InlineCall,
        InlineWarp,
        DebugInt,
        DebugPrk,
        Forwarded
    }
}
