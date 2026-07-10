using Iced.Intel;
using UndeadInterop.Meta;

namespace UndeadInterop.Meta.Hooking;

internal static class HookAnalyzer
{
    public static unsafe HookType GetHookType(this ExportFunction function, ExportFunction? cloneFunction = null)
    {
        if (function.IsForwardedExport)
            return HookType.Forwarded;

        HookType hookType = HookType.None;
        List<FunctionBlock> blocks = function.ReadInstructions();

        // no code detected, forwarded export address
        if (blocks.Count == 0)
            return HookType.Forwarded;

        foreach (FunctionBlock block in blocks)
        {
            if (block.PageProtect != 0x20 || block.PageState != 0x1000)
                return HookType.DebugPrk;

            foreach (Instruction instruction in block.Instructions)
            {
                // instruction will execute code outside of module
                if ((instruction.FlowControl == FlowControl.UnconditionalBranch ||
                    instruction.FlowControl == FlowControl.ConditionalBranch ||
                    instruction.FlowControl == FlowControl.IndirectBranch) &&
                    instruction.IsForwarded())
                {
                    hookType = HookType.InlineJmp;
                }
                // instruction will execute code outside of module
                else if (instruction.IsExecutor() &&
                    instruction.IsForwarded())
                {
                    hookType = HookType.InlineCall;
                }
                // instruction modifies return address (likely)
                else if ((instruction.Op0Kind == OpKind.Immediate64 &&
                    instruction.Mnemonic == Mnemonic.Push) ||
                    (instruction.Op0Kind == OpKind.Memory &&
                    instruction.OpCount == 2 &&
                    instruction.MemoryBase == Register.RSP &&
                    instruction.MemoryDisplacement64 >= 8 &&
                    instruction.MemoryDisplacement64 <= 24))
                {
                    hookType = HookType.Returning;
                }
                // instruction forces an interrupt
                else if (instruction.FlowControl == FlowControl.Interrupt &&
                    instruction.Immediate8 != 0x2e)
                {
                    hookType = HookType.DebugInt;
                }
                // instruction forces an exception
                else if (instruction.FlowControl == FlowControl.Exception)
                {
                    hookType = HookType.DebugPrk;
                }
            }
        }

        if (hookType == HookType.None && cloneFunction is not null)
        {
            int liveRva = (int)((nint)function.Address - function.Module.BaseAddress);
            int cloneRva = (int)((nint)cloneFunction.Value.Address - cloneFunction.Value.Module.BaseAddress);

            if (liveRva != cloneRva)
                return HookType.Forwarded;

            for (int i = 0; i < 512; i++)
            {
                if (function.Address[i] != cloneFunction.Value.Address[i])
                    return HookType.Tamper;
            }
        }

        return hookType;
    }
}
