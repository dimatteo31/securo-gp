namespace Securo.GlobalPlatform.Model
{
    public class Scp02InitializeResponseData : InitializeResponseData
    {
        public string SequenceCounter { get; set; }
        public virtual int SequenceCounterLength => 2;
        public override int CardChallengeLength => 6;

        public Scp02InitializeResponseData Parse(string initializeUpdateResponse)
        {
            var offset = 0;
            return new Scp02InitializeResponseData()
            {
                KeyDiversificationData = initializeUpdateResponse.Substring(offset, this.KeyDiversificationDataLength * 2),
                KeySetVersion = initializeUpdateResponse.Substring(offset += this.KeyDiversificationDataLength * 2, this.KeySetVersionLength * 2),
                ScpId = initializeUpdateResponse.Substring(offset += this.KeySetVersionLength * 2, this.ScpIdLength * 2),
                SequenceCounter = initializeUpdateResponse.Substring(offset += this.ScpIdLength * 2, this.SequenceCounterLength * 2),
                CardChallenge = initializeUpdateResponse.Substring(offset += this.SequenceCounterLength * 2, 2 * this.CardChallengeLength),
                CardCryptogram = initializeUpdateResponse.Substring(offset += this.CardChallengeLength * 2, this.CardCryptogramLength * 2),
            };
        }
    }
}