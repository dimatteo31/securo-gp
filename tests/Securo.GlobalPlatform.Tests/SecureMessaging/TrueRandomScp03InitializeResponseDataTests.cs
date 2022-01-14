using NUnit.Framework;

namespace Securo.GlobalPlatform.Model.Tests.SecureMessaging
{
    [TestFixture()]
    public class TrueRandomScp03InitializeResponseDataTests
    {
        [Test()]
        public void ParseTest()
        {
            // arrange
            const string expectedKeyDiversificationData = "00000346020614090044";
            const string expectedKeySetVersion = "01";
            const string expectedScpId = "03";
            const string expectedScpOption = "60";
            const string expectedCardChallenge = "D16D0B2E63C700D0";
            const string expectedCardCryptogram = "C31CA1DE694D3D08";
            var initalizeUpdateResponse = $"{expectedKeyDiversificationData}{expectedKeySetVersion}{expectedScpId}{expectedScpOption}{expectedCardChallenge}{expectedCardCryptogram}";

            // act
            var cut = new TrueRandomScp03InitializeResponseData();
            var result = cut.Parse(initalizeUpdateResponse);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedKeyDiversificationData, result.KeyDiversificationData);
            StringAssert.AreEqualIgnoringCase(expectedScpId, result.ScpId);
            StringAssert.AreEqualIgnoringCase(expectedKeySetVersion, result.KeySetVersion);
            StringAssert.AreEqualIgnoringCase(expectedScpOption, result.ScpOption);
            StringAssert.AreEqualIgnoringCase(expectedCardChallenge, result.CardChallenge);
            StringAssert.AreEqualIgnoringCase(expectedCardCryptogram, result.CardCryptogram);
        }
    }
}