namespace UndeadInterop.Meta.Hooking;

public enum HookType
{
    None,
    // function bytes differ from the filesystem clone but no specific hook was detected
    Tamper,
    InlineJmp,
    InlineCall,
    DebugInt,
    DebugPrk,
    DebugStep,
    // TODO: Forwarded is horribly broken until filesystem cloning is implemented
    Forwarded,
    Returning
}
