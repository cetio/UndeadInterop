namespace UndeadInterop.Meta.Hooking
{
    public enum HookType
    {
        NONE,
        INLINE_JMP,
        INLINE_CALL,
        INLINE_WARP,
        DEBUG_INT,
        DEBUG_PRK,
        FORWARDED
    }
}
