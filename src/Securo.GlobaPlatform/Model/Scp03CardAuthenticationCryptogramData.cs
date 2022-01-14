namespace Securo.GlobalPlatform.Model
{
    public class Scp03CardAuthenticationCryptogramData : Scp03HostAuthenticationCryptogramData
    {
        public override string IterationCounter => "00";
    }
}
