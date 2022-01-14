using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ICryptoProvider
    {
        CryptoProvider Name { get; }
        string Encrypt(string iv, string key, string input);
        string Decrypt(string iv, string key, string cryptogram);
    }
}