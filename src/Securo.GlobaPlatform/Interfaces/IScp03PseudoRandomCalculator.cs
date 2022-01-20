namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03PseudoRandomCalculator
    {
        string Generate(string key, string aid, string sequencecounter);
    }
}