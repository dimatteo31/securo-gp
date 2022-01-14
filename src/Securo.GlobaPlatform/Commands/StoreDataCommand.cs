using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Commands
{
    internal class StoreDataCommand : ApduCommand, IApduCommand
    {
        private readonly string Data;

        public StoreDataCommand(byte p1, byte p2, string data)
        {
            this.Class = 0x80;
            this.Instruction = 0xE2;
            this.P1 = p1;
            this.P2 = p2;
            this.Data = data;
        }

        public string Build()
        {
            return $"{this.Class.ToString("X2")}{this.Instruction.ToString("X2")}{this.P1.ToString("X2")}{this.P2.ToString("X2")}{this.Data.Length / 2}{this.Data}";
        }
    }
}