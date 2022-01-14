using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;
using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.Commands
{
    internal class InitalizeUpdateCommand : ApduCommand, IApduCommand
    {
        private readonly byte[] CardChallenge;

        public InitalizeUpdateCommand(byte p1, byte p2, string cardChallenge)
        {
            this.Class = 0x80;
            this.Instruction = (byte)CmdIns.InitializeUpdate;
            this.P1 = p1;
            this.P2 = p2;
            this.CardChallenge = Hex.Decode(cardChallenge);
            this.Le = 0x00;
            this.HasLe = true;
        }

        public string Build()
        {
            var apduByteArray = new byte[] { this.Class, this.Instruction, this.P1, this.P2, (byte)this.CardChallenge.Length }.Concat(this.CardChallenge).ToArray();
            if (this.HasLe)
            {
                apduByteArray = apduByteArray.Append(this.Le).ToArray();
            }

            return Hex.ToHexString(apduByteArray);
        }
    }
}