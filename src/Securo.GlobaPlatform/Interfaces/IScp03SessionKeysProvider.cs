using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03SessionKeysProvider
    {
        KeySet CalculateSessionKeys(string hostChallenge, string cardChallenge);
    }
}