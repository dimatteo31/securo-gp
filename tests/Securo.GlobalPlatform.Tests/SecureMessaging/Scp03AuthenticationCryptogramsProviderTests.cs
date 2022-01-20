using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    [TestFixture]
    public class Scp03AuthenticationCryptogramsProviderTests
    {
        [TestCaseSource("HostAuthenticationCryptogramData")]
        public void ShouldCalculateHostAuthCertificate(string cardChallenge, string hostChallenge, string key, string expectedHac)
        {
            // arrange & act
            var hacProvider = new Scp03HostAuthenticationCryptogramProvider(new List<IMacProvider>() { new AesCmacProvider() });
            var hac = hacProvider.Calculate(key, new Scp03HostAuthenticationCryptogramData() { CardChallenge = cardChallenge, HostChallenge = hostChallenge });

            // assert
            StringAssert.AreEqualIgnoringCase(expectedHac, hac);
        }

        [TestCaseSource("CardAuthenticationCryptogramData")]
        public void ShouldCalculateCardAuthCertificate(string cardChallenge, string hostChallenge, string key, string expectedHac)
        {
            // arrange & act
            var hacProvider = new Scp03CardAuthenticationCryptogramProvider(new List<IMacProvider>() { new AesCmacProvider() });
            var hac = hacProvider.Calculate(key, new Scp03CardAuthenticationCryptogramData() { CardChallenge = cardChallenge, HostChallenge = hostChallenge });

            // assert
            StringAssert.AreEqualIgnoringCase(expectedHac, hac);
        }

        public static IEnumerable<TestCaseData> HostAuthenticationCryptogramData
        {
            get
            {
                // aes-128
                yield return new TestCaseData(
                    "5D86C88B67378B54",
                    "0102030405060708",
                    "3bdfa3d50b6af293457a15f382954443",
                    "4500F6921E696CB4");

                // aes-256
                yield return new TestCaseData(
                    "794521D878979A6B",
                    "40C86DD58F3367F2",
                    "17a8eaa651fad017afbcc5277458a78d97f09893dbbf8e278c793e34b9ecd760",
                    "9982898519B1578A");
            }
        }

        public static IEnumerable<TestCaseData> CardAuthenticationCryptogramData
        {
            get
            {
                // aes-256
                yield return new TestCaseData(
                    "794521D878979A6B",
                    "40C86DD58F3367F2",
                    "17a8eaa651fad017afbcc5277458a78d97f09893dbbf8e278c793e34b9ecd760",
                    "A7444A2C8B4A4FBC");
            }
        }
    }
}