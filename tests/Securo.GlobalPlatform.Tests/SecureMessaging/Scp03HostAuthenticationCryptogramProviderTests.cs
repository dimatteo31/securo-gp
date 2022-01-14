using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    [TestFixture]
    public class Scp03HostAuthenticationCryptogramProviderTests
    {
        [TestCaseSource("CardAuthenticationCryptogramData")]
        public void ShouldCalculateHostAuthCertificate(string cardChallenge, string hostChallenge, string key, string expectedHac)
        {
            // arrange & act
            var hacProvider = new Scp03HostAuthenticationCryptogramProvider(new List<IMacProvider>() { new AesCmacProvider() });
            var hac = hacProvider.Calculate(key, new Scp03HostAuthenticationCryptogramData() { CardChallenge = cardChallenge, HostChallenge = hostChallenge });

            // assert
            StringAssert.AreEqualIgnoringCase(expectedHac, hac);
        }

        public static IEnumerable<TestCaseData> CardAuthenticationCryptogramData
        {
            get
            {
                yield return new TestCaseData(
                    "5D86C88B67378B54",
                    "0102030405060708",
                    "3bdfa3d50b6af293457a15f382954443",
                    "4500F6921E696CB4");
            }
        }
    }
}
