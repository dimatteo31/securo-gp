namespace Securo.GlobalPlatform.Model
{
    public class PseudoRandomScp03InitializeResponseData : TrueRandomScp03InitializeResponseData
    {
        public string SequenceCounter { get; set; }
        public virtual int SequenceCounterLength => 3;

        public override PseudoRandomScp03InitializeResponseData Parse(string initializeUpdateResponse)
        {
            var offset = 0;
            return new PseudoRandomScp03InitializeResponseData()
            {
                KeyDiversificationData = initializeUpdateResponse.Substring(offset, this.KeyDiversificationDataLength * 2),
                KeySetVersion = initializeUpdateResponse.Substring(offset += this.KeyDiversificationDataLength * 2, this.KeySetVersionLength * 2),
                ScpId = initializeUpdateResponse.Substring(offset += this.KeySetVersionLength * 2, ScpIdLength * 2),
                ScpOption = initializeUpdateResponse.Substring(offset += ScpIdLength * 2, ScpOptionLength * 2),
                CardChallenge = initializeUpdateResponse.Substring(offset += ScpOptionLength * 2, 2 * this.CardChallengeLength),
                CardCryptogram = initializeUpdateResponse.Substring(offset += this.CardChallengeLength * 2, this.CardCryptogramLength * 2),
                SequenceCounter = initializeUpdateResponse.Substring(offset += this.CardCryptogramLength * 2, SequenceCounterLength * 2)
            };
        }
    }
}