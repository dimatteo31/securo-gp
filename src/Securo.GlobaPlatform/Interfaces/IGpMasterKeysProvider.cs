using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IGpMasterKeysProvider
    {
        KeySet Provide();
    }
}