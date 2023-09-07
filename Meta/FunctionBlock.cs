using Iced.Intel;

namespace UndeadInterop.Meta
{
    internal struct FunctionBlock
    {
        public string LocalName;
        public List<Instruction> Instructions;
        public uint PageProtect;
        public uint PageState;

        public FunctionBlock(string localName, uint pageProtect, uint pageState)
        {
            LocalName = localName;
            Instructions = new List<Instruction>();
            PageProtect = pageProtect;
            PageState = pageState;
        }
    }
}
