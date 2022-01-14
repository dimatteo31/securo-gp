using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public interface ISecureContextProviderFactory
    {
        ISecureContextProvider Provide(ScpMode scpMode);
    }
}
