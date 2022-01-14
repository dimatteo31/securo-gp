using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ICardManager
    {
        string Aid { get; }
        void Select(string aid);
        void InitializeUpdate(byte keySetVersion, byte keyIdentifier, string hostChallenge);
        void ExternalAuthenticate(SecurityLevel securityLevel);
        void StoreData(string data);
        string GetData(byte tagMsb, byte tagLsb);
        CardResponse TransmitApdu(SecurityLevel secLevel, string command);
        SecureSessionDetails SecureSessionDetails { get; }
    }
}