namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03Level1SecureMessagingWrapper : IScp03SecureMessagingWrapper
    {
        string MacIv { get; }
        void SetUp(string iv, string key);
    }
}