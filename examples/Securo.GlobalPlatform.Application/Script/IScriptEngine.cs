using Securo.GlobalPlatform.Model;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.Application.Script
{
    public interface IScriptEngine
    {
        void Process(IEnumerable<string> commands);
    }
}
