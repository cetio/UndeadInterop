namespace UndeadInterop.Meta.Hooking
{
    public enum HookType
    {
        None,
        InlineJmp,
        InlineCall,
        Returning,
        DebugInt,
        DebugPrk,
        // TODO: Forwarded is horribly broken until filesystem cloning is implemented
        Forwarded
    }
}
