using Securo.GlobalPlatform.Interfaces;
using NUnit.Framework;
using NSubstitute;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Tests
{
    [TestFixture]
    public class CardManagerTests
    {
        private IApduTransmit mockedApduTransmit;
        private IGpMasterKeysProvider gpMasterKeysProvider;
        
        const string Aid = "a000000003000000";
        const int SwSuccess = 0x9000;

        [SetUp]
        public void SetUp()
        {
            mockedApduTransmit = Substitute.For<IApduTransmit>();
            gpMasterKeysProvider = Substitute.For<IGpMasterKeysProvider>();
            mockedApduTransmit.Send($"00a4040008{Aid}").Returns(new CardResponse() { StatusWord = SwSuccess });
            mockedApduTransmit.Send("80CA006600").Returns(new CardResponse() { StatusWord = SwSuccess, Data = "663F733D06072A864886FC6B01600C060A2A864886FC6B02020201630906072A864886FC6B03640B06092A864886FC6B040360660C060A2B060104012A026E0102" });
            gpMasterKeysProvider.Provide().Returns(new KeySet()
            {
                EncryptionKey = "404142434445464748494a4b4c4d4e4f",
                KeyEncryptionKey = "404142434445464748494a4b4c4d4e4f",
                MacKey = "404142434445464748494a4b4c4d4e4f"
            });
        }

        [Test()]
        public void ShouldInitializeUpdateAndExternalAuthenticate()
        {
            // arrange
            const string hostChallenge = "7E7B7BD6BBACED6B";
            const string cardChallenge = "DF5BF9B50B977F64";
            const string cardCryptogram = "D0E982BC2F7192A6";
            byte expectedScpId = 0x03;
            byte keySetVersion = 0x00;
            byte keyId = 0x00;
            const string expectedMacIv = "4646df95f109018728bf3159fc2533f0";
            const string expectedSessionEncryptionKey = "e16dadc8c5b96878afa5f69d002ac488";
            const string expectedSessionMacKey = "34eef3c224b32dd9d29c0b7bddf385d0";

            mockedApduTransmit.Send("80500000087e7b7bd6bbaced6b00")
                .Returns(new CardResponse()
                {
                    StatusWord = SwSuccess,
                    Data = $"0000034602061409004401{expectedScpId.ToString("X2")}60{cardChallenge}{cardCryptogram}"
                });

            mockedApduTransmit.Send("8482030010eae9727a80e0c4ed4646df95f1090187")
                .Returns(new CardResponse()
                {
                    StatusWord = SwSuccess
                });

            // act
            var cardManager = new CardManager(mockedApduTransmit, gpMasterKeysProvider);
            cardManager.Select(Aid);
            cardManager.InitializeUpdate(keySetVersion, keyId, hostChallenge);
            cardManager.ExternalAuthenticate(SecurityLevel.Mac_Enc);

            // assert
            Assert.AreEqual(expectedSessionEncryptionKey, cardManager.SecureSessionDetails.SessionKeys.EncryptionKey);
            Assert.AreEqual(expectedSessionMacKey, cardManager.SecureSessionDetails.SessionKeys.MacKey);
            Assert.AreEqual(expectedScpId, cardManager.SecureSessionDetails.ScpInfo.ScpIdentifier);
            Assert.AreEqual(expectedMacIv, cardManager.SecureSessionDetails.MacIv);
        }
    }
}
