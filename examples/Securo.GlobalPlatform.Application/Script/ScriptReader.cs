using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Securo.GlobalPlatform.Application.Script
{
    public class ScriptReader : IScriptReader
    {
        public IEnumerable<string> ReadScript(string scriptPath)
        {
            var scriptLines = File.ReadAllLines(scriptPath);
            return scriptLines.Where(x => !x.StartsWith("//") || String.IsNullOrEmpty(x));
        }
    }
}
