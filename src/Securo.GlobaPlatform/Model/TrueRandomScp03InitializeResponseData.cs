namespace Securo.GlobalPlatform.Model
{
    public class TrueRandomScp03InitializeResponseData : Scp03InitializeResponseData
    {
        public virtual TrueRandomScp03InitializeResponseData Parse(string initializeUpdateResponse)
        {
            var offset = 0;
            return new TrueRandomScp03InitializeResponseData()
            {
                KeyDiversificationData = initializeUpdateResponse.Substring(offset, this.KeyDiversificationDataLength * 2),
                KeySetVersion = initializeUpdateResponse.Substring(offset += this.KeyDiversificationDataLength * 2, this.KeySetVersionLength * 2),
                ScpId = initializeUpdateResponse.Substring(offset += this.KeySetVersionLength * 2, ScpIdLength * 2),
                ScpOption = initializeUpdateResponse.Substring(offset += ScpIdLength * 2, ScpOptionLength * 2),
                CardChallenge = initializeUpdateResponse.Substring(offset += ScpOptionLength * 2, 2 * this.CardChallengeLength),
                CardCryptogram = initializeUpdateResponse.Substring(offset += this.CardChallengeLength * 2, this.CardCryptogramLength * 2)
            };
        }
    }
}