using System.Collections.Generic;

namespace Securo.GlobalPlatform.Application.Script
{
    public interface IScriptReader
    {
        IEnumerable<string> ReadScript(string scriptPath);
    }
}
