using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03HostAuthenticationCryptogramProvider : IAuthenticationCryptogramProvider<Scp03HostAuthenticationCryptogramData>
    {
        private IEnumerable<IMacProvider> macProviders;
        private const int HacLengthInBytes = 8;

        public Scp03HostAuthenticationCryptogramProvider(IEnumerable<IMacProvider> macProviders)
        {
            this.macProviders = macProviders;
        }

        public string Calculate(string key, Scp03HostAuthenticationCryptogramData crytpogramDetails)
        {
            var inputData = crytpogramDetails.Build();
            return this.macProviders.Single(x => x.Name == MacProvider.AesCmacProvider).Generate(string.Empty, key, inputData).Substring(0, HacLengthInBytes * 2);
        }

        public bool Verify(string key, Scp03HostAuthenticationCryptogramData crytpogramDetails, string cardCryptogram)
        {
            throw new System.NotImplementedException();
        }
    }
}