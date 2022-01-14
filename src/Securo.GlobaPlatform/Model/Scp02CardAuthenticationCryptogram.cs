namespace Securo.GlobalPlatform.Model
{
    public class Scp02CardAuthenticationCryptogram : AuthenticationCryptogram
    {
        public string Counter { get; set; }

        public override string Build()
        {
            return $"{this.HostChallenge}{this.Counter}{this.CardChallenge}";
        }
    }
}
