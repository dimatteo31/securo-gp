using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    [TestFixture]
    public class Scp02CardAuthenticationCryptogramProviderTests
    {
        private IAuthenticationCryptogramProvider<Scp02CardAuthenticationCryptogram> cut;

        [TestCaseSource("CardAuthenticationCryptogramData")]
        public void ShouldCalculateCardAuthenticationCryptogram(string hostChallenge, string intializeUpdateResponse, string sessionKey)
        {
            // arrange
            var scp02InitializeResponseData = new Scp02InitializeResponseData().Parse(intializeUpdateResponse);
            var cardAuthCryptogramModel = new Scp02CardAuthenticationCryptogram()
            {
                CardChallenge = scp02InitializeResponseData.CardChallenge,
                Counter = scp02InitializeResponseData.SequenceCounter,
                HostChallenge = hostChallenge
            };
            var expectedCryptogram = scp02InitializeResponseData.CardCryptogram;

            // act
            this.cut = new Scp02CardAuthenticationCryptogramProvider(new List<IMacProvider>() { new RetailMacProvider() });
            var calculatedCac = this.cut.Calculate(sessionKey, cardAuthCryptogramModel);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCryptogram, calculatedCac);
        }
        
        public static IEnumerable<TestCaseData> CardAuthenticationCryptogramData
        {
            get
            {
                // hostChallenge, intializeUpdateResponse, sessionKey
                yield return new TestCaseData(
                    "D2A9C8944CE46FAC",
                    "0000417100760397383602020017D5E0E4354592044B00773A3D6986",
                    "56a1dc0a4b4165c9ed464fab97380abd");
            }
        }
    }
}
