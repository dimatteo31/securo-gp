namespace Securo.GlobalPlatform.Model
{
    public class SecureSessionDetails
    {
        public string MacIv { get; set; }
        public string EncryptionIv { get; set; }
        public int IvCounter{ get; set; }
        public string HostChallenge { get; set; }
        public KeySet SessionKeys { get; set; }
        public string CardChallenge { get; set; }
        public string SequenceCounter { get; set; }
        public ScpInfo ScpInfo { get; set; }
        public string CardCryptogram { get; set; }
    }
}
