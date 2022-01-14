using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Securo.GlobalPlatform.Model
{
    public abstract class AuthenticationCryptogram
    {
        public string CardChallenge { get; set; }
        public string HostChallenge { get; set; }
        public abstract string Build();
    }
}
