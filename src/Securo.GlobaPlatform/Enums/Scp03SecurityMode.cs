namespace Securo.GlobalPlatform.Enums
{
    public enum Scp03SecurityMode
    {
        NoResponseMac_ResponseEncryption = 0x00,
        ResponseMac_NoResponseEncryption = 0x20,
        ResponseMac_ResponseEncryption = 0x60,
    }
}