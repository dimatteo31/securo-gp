using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Linq;

namespace Securo.GlobalPlatform.Commands
{
    internal class StoreDataCommand : ApduCommand, IApduCommand
    {
        private readonly byte[] Data;

        public StoreDataCommand(byte p1, byte p2, string data)
        {
            this.Class = 0x80;
            this.Instruction = (byte)InstructionCode.StoreData;
            this.P1 = p1;
            this.P2 = p2;
            this.Data = Hex.Decode(data);
        }

        public string Build()
        {
            var apduByteArray = new byte[] { this.Class, this.Instruction, this.P1, this.P2, (byte)this.Data.Length }.Concat(Data).ToArray();
            return Hex.ToHexString(apduByteArray);
        }
    }
}