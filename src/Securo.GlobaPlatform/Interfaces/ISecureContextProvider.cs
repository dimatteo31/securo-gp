using Securo.GlobalPlatform.Model;
using System.Threading.Tasks;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ISecureContextProvider
    {
        void InitializeSecureContext(SecureSessionDetails secureSessionDetails);
        Task<string> Wrap(SecurityLevel securityLevel, string command);
        Task<string> Unwrap(SecurityLevel securityLevel, string command);
        SecureSessionDetails SecureSessionDetails { get; }
        Task<string> CalculateHostCrypogram();
    }
}