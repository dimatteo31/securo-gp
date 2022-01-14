namespace Securo.GlobalPlatform.Model
{
    public class KeySet
    {
        public string EncryptionKey { get; set; }
        public string MacKey { get; set; }
        public string KeyEncryptionKey { get; set; }
        public string RmacKey { get; set; }
    }
}