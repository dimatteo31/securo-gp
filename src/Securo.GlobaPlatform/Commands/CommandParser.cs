using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;
using Securo.GlobalPlatform.Interfaces;

namespace Securo.GlobalPlatform.Commands
{
    public class CommandParser : ICommandParser
    {
        public string Build(ApduCommand command)
        {
            var commandHex = new byte[]
            {
                command.Class,
                command.Instruction,
                command.P1,
                command.P2,
                command.Lc
            }.Concat(command.Data);

            if (command.HasLe)
            {
                return Hex.ToHexString(commandHex.Append(command.Le).ToArray());
            }

            return Hex.ToHexString(commandHex.ToArray());
        }

        public ApduCommand Parse(string command)
        {
            var hexCommand = Hex.Decode(command);
            var apdu = new ApduCommand()
            {
                Class = hexCommand[0],
                Instruction = hexCommand[1],
                P1 = hexCommand[2],
                P2 = hexCommand[3],
                Lc = hexCommand[4],
                Data = hexCommand.Skip(5).Take(hexCommand[4]).ToArray()
            };
            try
            {
                var le = hexCommand.Skip(5 + hexCommand[4]).ToArray()[0];
                apdu.Le = le;
                apdu.HasLe = true;
            }
            catch {
                apdu.HasLe = false;
            }

            return apdu;
        }
    }
}
