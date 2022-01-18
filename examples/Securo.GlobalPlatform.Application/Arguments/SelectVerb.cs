using CommandLine;

namespace Securo.GlobalPlatform.Application.Arguments
{
    [Verb("select", HelpText = "Selects GP applet")]
    public class SelectVerb
    {
        [Option("aid", HelpText = "AID of given GP applet")]
        public string Aid { get; set; }
    }
}
