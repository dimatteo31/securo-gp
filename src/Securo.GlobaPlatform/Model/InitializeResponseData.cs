namespace Securo.GlobalPlatform.Model
{
    public class InitializeResponseData
    {
        public string KeyDiversificationData { get; set; }
        public virtual int KeyDiversificationDataLength => 10;

        public string KeySetVersion { get; set; }
        public virtual int KeySetVersionLength => 1;

        public string ScpId { get; set; }
        public virtual int ScpIdLength => 1;

        public string CardChallenge { get; set; }
        public virtual int CardChallengeLength { get; set; }

        public string CardCryptogram { get; set; }
        public virtual int CardCryptogramLength => 8;

        public string GetScpId(string initializeResponseData)
        {
            return initializeResponseData.Substring(KeyDiversificationDataLength * 2 + KeySetVersionLength * 2,
                ScpIdLength * 2);
        }
    }
}