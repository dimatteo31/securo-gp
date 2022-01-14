namespace Securo.GlobalPlatform.Enums
{
    public enum Scp02Configuration : byte
    {
        NoIcvEncryption_TrueRandom = 0x05,
        IcvEncryption_TrueRandom = 0x15,
        NoIcvEncryption_PseudoRandom = 0x45,
        IcvEncryption_PseudoRandom = 0x55
    }
}