using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp02SessionKeysProvider
    {
        KeySet CalculateSessionKeys(string counter);
    }
}