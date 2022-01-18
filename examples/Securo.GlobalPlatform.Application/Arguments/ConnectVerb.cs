using CommandLine;

namespace Securo.GlobalPlatform.Application.Arguments
{
    [Verb("connect", HelpText = "Performs connection to PCSC reader (card must be inserted)")]
    public class ConnectVerb
    {
        [Option("reader", Required = true, HelpText = "PCSC reader name")]
        public string PcscReader { get; set; }
    }
}
