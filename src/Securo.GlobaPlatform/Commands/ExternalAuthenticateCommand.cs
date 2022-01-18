using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;
using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.Commands
{
    internal class ExternalAuthenticateCommand : ApduCommand, IApduCommand
    {
        private readonly byte[] HostCryptogramWithCmac;

        public ExternalAuthenticateCommand(byte p1, string hostCryptogramWithCmac)
        {
            this.Class = 0x84;
            this.Instruction = (byte)InstructionCode.ExternalAuthenticate;
            this.P1 = p1;
            this.P2 = 0x00;
            this.HostCryptogramWithCmac = Hex.Decode(hostCryptogramWithCmac);
        }

        public string Build()
        {
            var apduByteArray = new byte[] { this.Class, this.Instruction, this.P1, this.P2, (byte)this.HostCryptogramWithCmac.Length }.Concat(this.HostCryptogramWithCmac).ToArray();
            return Hex.ToHexString(apduByteArray);
        }
    }
}