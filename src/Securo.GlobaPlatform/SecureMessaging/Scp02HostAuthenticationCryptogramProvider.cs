using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp02HostAuthenticationCryptogramProvider : IAuthenticationCryptogramProvider<Scp02HostAuthenticationCryptogramData>
    {
        private readonly IMacProvider retailMac;
        private const string IvZeros = "0000000000000000";

        public Scp02HostAuthenticationCryptogramProvider(IEnumerable<IMacProvider> macProviders)
        {
            this.retailMac = macProviders.Single(x => x.Name == MacProvider.Retail);
        }

        public string Calculate(string key, Scp02HostAuthenticationCryptogramData crytpogramDetails)
        {
            var input = crytpogramDetails.Build();
            return this.retailMac.Generate(IvZeros, key, input);
        }

        public bool Verify(string key, Scp02HostAuthenticationCryptogramData crytpogramDetails, string cardCryptogram)
        {
            throw new System.NotImplementedException();
        }
    }
}