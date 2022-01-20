using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03CardAuthenticationCryptogramProvider : IAuthenticationCryptogramProvider<Scp03CardAuthenticationCryptogramData>
    {
        private IEnumerable<IMacProvider> macProviders;
        private const int HacLengthInBytes = 8;

        public Scp03CardAuthenticationCryptogramProvider(IEnumerable<IMacProvider> macProviders)
        {
            this.macProviders = macProviders;
        }

        public string Calculate(string key, Scp03CardAuthenticationCryptogramData crytpogramDetails)
        {
            var inputData = crytpogramDetails.Build();
            return this.macProviders.Single(x => x.Name == MacProvider.AesCmacProvider).Generate(string.Empty, key, inputData).Substring(0, HacLengthInBytes * 2);
        }

        public bool Verify(string key, Scp03CardAuthenticationCryptogramData crytpogramDetails, string cardCryptogram)
        {
            var cac = Calculate(key, crytpogramDetails);
            if (String.Compare(cac, cardCryptogram, true) != 0)
            {
                return false;
            }

            return true;
        }
    }
}