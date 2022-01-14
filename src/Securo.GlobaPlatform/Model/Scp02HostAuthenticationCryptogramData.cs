namespace Securo.GlobalPlatform.Model
{
    public class Scp02HostAuthenticationCryptogramData : AuthenticationCryptogram
    {
        public string Counter { get; set; }

        public override string Build()
        {
            return $"{this.Counter}{this.CardChallenge}{this.HostChallenge}";
        }
    }
}
