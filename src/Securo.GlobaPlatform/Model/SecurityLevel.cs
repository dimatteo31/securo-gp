using System.Text.Json.Serialization;

namespace Securo.GlobalPlatform.Model
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum SecurityLevel : byte
    {
        /// <summary>
        /// No secure messaging expected
        /// </summary>
        None = 0x00,
        /// <summary>
        /// C-MAC
        /// </summary>
        Mac = 0x01,
        /// <summary>
        /// C-DECRYPTION and C-MAC
        /// </summary>
        Mac_Enc = 0x03,
        /// <summary>
        /// C-MAC and R-MAC
        /// </summary>
        Mac_RMac = 0x11,
        /// <summary>
        /// C-DECRYPTION, C-MAC, and R-MAC
        /// </summary>
        Mac_Enc_RMac = 0x13,
        /// <summary>
        /// C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC
        /// </summary>
        Mac_Enc_REnc_RMac = 0x33,
    }
}
