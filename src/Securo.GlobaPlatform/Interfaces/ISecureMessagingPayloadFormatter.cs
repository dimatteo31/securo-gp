using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public interface ISecureMessagingPayloadFormatter
    {
        string Format(SecureMessagingMode secureMessagingMode, ApduCommand apdu);
    }
}