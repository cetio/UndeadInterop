namespace UndeadInterop.Meta.Hooking;

public enum HookType
{
    None,
    InlineJmp,
    InlineCall,
    DebugInt,
    DebugPrk,
    DebugStep,
    // TODO: Forwarded is horribly broken until filesystem cloning is implemented
    Forwarded,
    Returning
}
