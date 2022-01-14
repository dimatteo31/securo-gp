namespace Securo.GlobalPlatform.Model
{
    public class Scp03HostAuthenticationCryptogramData : AuthenticationCryptogram
    {
        public virtual string IterationCounter => "01";
        protected string label = "0000000000000000000000";

        public override string Build()
        {
            return $"{label}{IterationCounter}00004001{this.HostChallenge}{this.CardChallenge}";
        }
    }
}
