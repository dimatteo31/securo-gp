using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;
using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.Commands
{
    internal class SelectApduCommand : ApduCommand, IApduCommand
    {
        private readonly byte[] Aid;

        public SelectApduCommand(byte p1, byte p2, string aid)
        {
            this.Class = 0x00;
            this.Instruction = (byte)CmdIns.Select;
            this.P1 = p1;
            this.P2 = p2;
            this.Aid = Hex.Decode(aid);
        }

        public string Build()
        {
            var apduByteArray = new byte[] { this.Class, this.Instruction, this.P1, this.P2, (byte)this.Aid.Length }.Concat(this.Aid).ToArray();
            return Hex.ToHexString(apduByteArray);
        }
    }
}