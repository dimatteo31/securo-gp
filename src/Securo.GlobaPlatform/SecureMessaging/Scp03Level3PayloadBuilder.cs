using Securo.GlobalPlatform.Commands;
using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Interfaces;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03Level3PayloadBuilder : IScp03PayloadBuilder
    {
        private readonly ICommandParser commandParser;

        public Scp03Level3PayloadBuilder()
        {
            commandParser = new CommandParser();
        }

        public string UpdatedCommand => throw new System.NotImplementedException();

        public string BuildPayload(string encrpytedData, string command)
        {
            var newApduCommand = this.commandParser.Parse(command);
            var hexEncryptedData = Hex.Decode(encrpytedData);
            newApduCommand.Class |= 0x04;
            newApduCommand.Lc = (byte)hexEncryptedData.Length;
            newApduCommand.HasLe = false;
            newApduCommand.Data = hexEncryptedData;
            return this.commandParser.Build(newApduCommand);
        }
    }
}