using CommandLine;

namespace Securo.GlobalPlatform.Application.Arguments
{
    [Verb("set_keys", HelpText = "Sets GP keys [enc|mac|dek]")]
    public class SetGpKeysVerb
    {
        [Option("key_enc", HelpText = "Secure channel encryption key")]
        public string EncKey { get; set; }

        [Option("key_mac", HelpText = "Secure channel message authentication code key")]
        public string MacKey { get; set; }

        [Option("key_dek", HelpText = "Data encryption key")]
        public string DekKey { get; set; }
    }
}
