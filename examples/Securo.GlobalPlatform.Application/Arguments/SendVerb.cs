using CommandLine;

namespace Securo.GlobalPlatform.Application.Arguments
{
    [Verb("send", HelpText = "Sends APDU with security level requested during sc_open command")]
    public class SendVerb
    {
        [Option("apdu", Required = true, HelpText = "APDU value")]
        public string ApduCommand { get; set; }
    }
}
