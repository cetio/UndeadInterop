using Iced.Intel;

namespace UndeadInterop.Meta.Hooking
{
    internal static class HookAnalyzer
    {
        public static unsafe HookType GetHookType(this ExportFunction function)
        {
            HookType hookType = HookType.NONE;
            List<FunctionBlock> blocks = function.ReadInstructions();

            // no code detected, forwarded export address
            if (blocks.Count == 0)
                return HookType.FORWARDED;

            foreach (FunctionBlock block in blocks)
            {
                if (block.PageProtect != 0x20 || block.PageState != 0x1000)
                    return HookType.DEBUG_PRK;

                foreach (Instruction instruction in block.Instructions)
                {
                    // instruction will execute code outside of module
                    if ((instruction.FlowControl == FlowControl.UnconditionalBranch ||
                        instruction.FlowControl == FlowControl.ConditionalBranch ||
                        instruction.FlowControl == FlowControl.IndirectBranch) &&
                        instruction.IsForwarded())
                    {
                        hookType = HookType.INLINE_JMP;
                    }
                    // instruction will execute code outside of module
                    else if (instruction.IsExecutor() &&
                        instruction.IsForwarded())
                    {
                        hookType = HookType.INLINE_CALL;
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
                        hookType = HookType.INLINE_WARP;
                    }
                    // instruction forces an interrupt
                    else if (instruction.FlowControl == FlowControl.Interrupt &&
                        instruction.Immediate8 != 0x2e)
                    {
                        hookType = HookType.DEBUG_INT;
                    }
                    // instruction forces an exception
                    else if (instruction.FlowControl == FlowControl.Exception)
                    {
                        hookType = HookType.DEBUG_PRK;
                    }
                }
            }

            return hookType;
        }
    }
}
