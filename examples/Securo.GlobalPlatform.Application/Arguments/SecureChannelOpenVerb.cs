using CommandLine;

namespace Securo.GlobalPlatform.Application.Arguments
{
    [Verb("open", HelpText = "Opens secure channel with GP card")]
    public class SecureChannelOpenVerb
    {
        [Option("scp", HelpText = "Secure channel security level: [None=0x00|Mac=0x01|Mac_Enc=0x03|Mac_RMac=0x11|Mac_Enc_RMac=0x13|Mac_Enc_REnc_RMac=0x33]")]
        public string SecurityLevel { get; set; }

        [Option("kid", HelpText = "Key indentifier")]
        public int KeyId { get; set; }

        [Option("kver", HelpText = "Keyset version number in the range of 0x00 to 0x7F")]
        public int KeySetVersion { get; set; }
    }
}
