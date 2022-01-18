using CommandLine;
namespace Securo.GlobalPlatform.Application.Arguments
{
    public class Options
    {
        [Option("script", Required = true, HelpText = "{Path to input script file (txt file)")]
        public string Script { get; set; }
    }
}
