using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03SecureMessagingWrapper
    {
        SecurityLevel SecurityLevel { get; }
        string Wrap(string command);
        string Unwrap(string response);
    }
}