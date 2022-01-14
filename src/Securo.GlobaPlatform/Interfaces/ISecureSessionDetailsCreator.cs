using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ISecureSessionDetailsCreator
    {
        SecureSessionDetails Create(string input);
    }
}