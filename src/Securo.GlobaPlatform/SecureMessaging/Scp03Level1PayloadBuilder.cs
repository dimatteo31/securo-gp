using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Interfaces;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03Level1PayloadBuilder : IScp03PayloadBuilder
    {
        const int CmacSize = 0x08;
        private readonly ICommandParser commandParser;
        public string UpdatedCommand { get; private set; }

        public Scp03Level1PayloadBuilder()
        {
            commandParser = new CommandParser();
        }

        public string BuildPayload(string iv, string command)
        {
            var newApduCommand = this.commandParser.Parse(command);
            newApduCommand.Class |= 0x04;
            newApduCommand.Lc += CmacSize;
            newApduCommand.HasLe = false;
            this.UpdatedCommand = this.commandParser.Build(newApduCommand);
            var payload = $"{iv}{ this.UpdatedCommand}";
            return payload;
        }
    }
}