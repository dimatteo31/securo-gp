namespace Securo.GlobalPlatform.Model
{
    public class Scp03InitializeResponseData : InitializeResponseData
    {
        public string ScpOption { get; set; }
        public virtual int ScpOptionLength => 1;
        public override int CardChallengeLength => 8;
        public override int CardCryptogramLength => 8;

        public string GetScpOption(string initializeResponseData)
        {
            return initializeResponseData.Substring(KeyDiversificationDataLength * 2 + KeySetVersionLength * 2 + ScpIdLength * 2, ScpOptionLength * 2);
        }
    }
}