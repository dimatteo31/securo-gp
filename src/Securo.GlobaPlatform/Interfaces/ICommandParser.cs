using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ICommandParser
    {
        ApduCommand Parse(string command);
        string Build(ApduCommand command);
    }
}
