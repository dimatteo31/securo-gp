using CommandLine;
using Securo.GlobalPlatform.Application.Arguments;
using Securo.GlobalPlatform.Application.Script;
using System;

[assembly: log4net.Config.XmlConfigurator(ConfigFile = "log4net.config", Watch = true)]

namespace Securo.GlobalPlatform.Application
{
    class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options> (args)
             .WithParsed<Options>(o =>
             {
                 var script = new ScriptReader().ReadScript(o.Script);
                 new ScriptEngine().Process(script);
                 return;
             });
        }
    }
}
