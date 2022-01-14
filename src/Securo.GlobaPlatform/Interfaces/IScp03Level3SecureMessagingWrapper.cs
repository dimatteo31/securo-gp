namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03Level3SecureMessagingWrapper : IScp03SecureMessagingWrapper
    {
        string EncryptedIv { get; }
        void SetUp(string iv, string key, int counter);
    }
}