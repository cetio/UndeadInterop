using Iced.Intel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace UndeadInterop.Meta
{
    internal static class FunctionAnalyzer
    {
        [DllImport("kernel32.dll")]
        private static extern unsafe int VirtualQuery(byte* lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        private struct MEMORY_BASIC_INFORMATION
        {
            public nint BaseAddress;
            public nint AllocationBase;
            public uint AllocationProtect;
            public nint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private static List<Instruction> forwardBranches = new List<Instruction>();

        public static unsafe List<FunctionBlock> ReadInstructions(this ExportFunction function)
        {
            List<FunctionBlock> blocks = new List<FunctionBlock>();
            ReadInstructions(function.Address, function.Module, blocks);

            return blocks;
        }

        private static unsafe void ReadInstructions(byte* address, ProcessModule module, List<FunctionBlock> blocks, Instruction? source = null)
        {
            // Determine the function block name based on the source instruction
            string name = source == null ? "main" : "loc-" + ((Instruction)source).GetTargetAddress().ToString("X8");
            VirtualQuery(address, out MEMORY_BASIC_INFORMATION info, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

            // Create a new function block or reuse the last one if the name matches
            FunctionBlock block = blocks.Count != 0
                ? blocks.Last().LocalName == name
                    ? blocks.Last()
                    : new FunctionBlock(name, info.Protect, info.State)
                : new FunctionBlock(name, info.Protect, info.State);

            // Create a buffer for instructions
            List<Instruction> buffer = new List<Instruction>();
            Decoder decoder = Decoder.Create(64, new Span<byte>(address, 512).ToArray());

            // Check if the address is forwarded (outside the module's memory range)
            if (IsForwarded(module, address))
            {
                // If the instruction source is not null, add it to the list of forward branches
                if (source != null)
                    forwardBranches.Add((Instruction)source);

                return;
            }

            // Decode instructions until the buffer is full or the last instruction is a leading instruction
            while (decoder.IP < 512 && !buffer.LastOrDefault().IsLeading())
            {
                decoder.Decode(out Instruction instruction);
                buffer.Add(instruction);
                block.Instructions.Add(instruction);
            }

            // Add the function block to the list of blocks
            blocks.Add(block);

            // If the last instruction in the buffer is not a leading instruction, recursively call ReadInstructions with the next address
            if (!buffer.LastOrDefault().IsLeading())
                ReadInstructions(address + 512, module, blocks);

            // Check if any new blocks can be generated from the current block, we won't touch far branches because they won't be local
            foreach (Instruction instruction in buffer)
            {
                if (instruction.IsExecutor() &&
                    instruction.IsNearBranch() &&
                    instruction.GetTargetAddress() != 0 &&
                    instruction != source)
                {
                    ReadInstructions(address + instruction.GetTargetAddress(), module, blocks, instruction);
                }
            }
        }

        private static unsafe bool IsForwarded(ProcessModule module, byte* address)
        {
            return (nint)address - module.BaseAddress > module.ModuleMemorySize ||
                (nint)address - module.BaseAddress < 0;
        }

        /// <summary>
        /// Returns if the instruction will transfer execution to a module that it doesn't reside in.
        /// </summary>
        public static bool IsForwarded(this Instruction instruction)
        {
            return forwardBranches.Contains(instruction);
        }

        /// <summary>
        /// Returns if the instruction will end the execution safely, like RET, JMP NEAR, JMP FAR, etc.
        /// </summary>
        public static bool IsLeading(this Instruction instruction)
        {
            return instruction.FlowControl == FlowControl.Return ||
                instruction.FlowControl == FlowControl.IndirectBranch ||
                instruction.FlowControl == FlowControl.UnconditionalBranch;
        }

        /// <summary>
        /// Returns if the instruction will begin execution, like JMP NEAR, JMP FAR, CALL, etc.
        /// </summary>
        public static bool IsExecutor(this Instruction instruction)
        {
            return instruction.FlowControl == FlowControl.UnconditionalBranch ||
                instruction.FlowControl == FlowControl.ConditionalBranch ||
                instruction.FlowControl == FlowControl.IndirectBranch ||
                instruction.FlowControl == FlowControl.IndirectCall ||
                instruction.FlowControl == FlowControl.Call;
        }

        /// <summary>
        /// Returns if the instruction is a near branch instruction.
        /// </summary>
        public static bool IsNearBranch(this Instruction instruction)
        {
            return instruction.HasOpKind(OpKind.NearBranch16) ||
                instruction.HasOpKind(OpKind.NearBranch32) ||
                instruction.HasOpKind(OpKind.NearBranch64);
        }

        /// <summary>
        /// Returns the target address of an executor instruction.
        /// </summary>
        public static ulong GetTargetAddress(this Instruction instruction)
        {
            return instruction.IsNearBranch()
                ? instruction.NearBranchTarget
                : instruction.FarBranchSelector;
        }
    }
}
