using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using Securo.GlobalPlatform.Interfaces;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp02SecureMessagingPayloadBuilder : ISecureMessagingPayloadFormatter
    {
        const int MacSize = 0x08;
        const int DesBlockSize = 0x08;

        private readonly ICommandParser commandParser;

        public Scp02SecureMessagingPayloadBuilder(ICommandParser commandParser)
        {
            this.commandParser = commandParser;
        }

        public string Format(SecureMessagingMode secureMessagingMode, ApduCommand apdu)
        {
            switch(secureMessagingMode)
            {
                case SecureMessagingMode.Level0:
                    return commandParser.Build(apdu);
                case SecureMessagingMode.Level1:
                    return BuildPayloadForLevel1(this.commandParser.Build(apdu));
                case SecureMessagingMode.Level3:
                    return BuildPayloadForLevel3(this.commandParser.Build(apdu));
                default:
                    throw new InvalidOperationException();
            }
        }

        private string BuildPayloadForLevel1(string apdu)
        {
            var apduCmd = this.commandParser.Parse(apdu);
            apduCmd.Class |= 0x04;
            apduCmd.Lc += MacSize;
            apduCmd.HasLe = false;
            return commandParser.Build(apduCmd);
        }

        private string BuildPayloadForLevel3(string apdu)
        {
            var apduCommand = commandParser.Parse(apdu);
            var paddedData = Hex.ToHexString(apduCommand.Data).ApplyPadding(DesBlockSize);
            return Hex.ToHexString(paddedData);
        }
    }
}