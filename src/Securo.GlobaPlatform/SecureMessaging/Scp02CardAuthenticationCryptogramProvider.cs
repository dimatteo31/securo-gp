using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp02CardAuthenticationCryptogramProvider : IAuthenticationCryptogramProvider<Scp02CardAuthenticationCryptogram>
    {
        private readonly IMacProvider retailMac;
        private const string IvZeros = "0000000000000000";

        public Scp02CardAuthenticationCryptogramProvider(IEnumerable<IMacProvider> macProviders)
        {
            this.retailMac = macProviders.Single(x => x.Name == MacProvider.Retail);
        }

        public string Calculate(string key, Scp02CardAuthenticationCryptogram crytpogramDetails)
        {
            var input = crytpogramDetails.Build();
            return this.retailMac.Generate(IvZeros, key, input);
        }

        public bool Verify(string cardCryptogram)
        {
            throw new System.NotImplementedException();
        }
    }
}