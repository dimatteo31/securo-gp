namespace Securo.GlobalPlatform.Model
{
    public class Scp03CardAuthenticationCryptogram : AuthenticationCryptogram
    {
        public string Label { get; set; }
        public string DerivationConstant { get; set; }
        public string L { get; set; }
        public string IterationCounter { get; set; }

        public override string Build()
        {
            throw new System.NotImplementedException();
        }
    }
}
