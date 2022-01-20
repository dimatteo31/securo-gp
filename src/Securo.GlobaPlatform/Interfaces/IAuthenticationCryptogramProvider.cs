using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IAuthenticationCryptogramProvider<T>
    {
        string Calculate(string key, T crytpogramDetails);
        bool Verify(string key, T crytpogramDetails, string cryptogramToVerify);
    }
}
