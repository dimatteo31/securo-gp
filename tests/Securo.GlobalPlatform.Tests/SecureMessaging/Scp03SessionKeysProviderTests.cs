using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;
using Securo.GlobalPlatform.Tests.TestData;
using NSubstitute;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    public class Scp03SessionKeysProviderTests
    {
        [TestCaseSource("SessionKeysTestDataAes128")]
        public void ShouldCalculateSessionKeysAes128(KeySet mainKeys, KeySet expectedKeys)
        {
            // arrange 
            const string cardChallenge = "5D86C88B67378B54";
            const string hostChallenge = "0102030405060708";

            // act
            var mockedKeysProvider = Substitute.For<IGpMasterKeysProvider>();
            mockedKeysProvider.Provide().Returns(mainKeys);
            var cut = new Scp03SessionKeysProvider(mockedKeysProvider, new List<IMacProvider>() { new AesCmacProvider() });
            var sessionKeys = cut.CalculateSessionKeys(hostChallenge, cardChallenge);

            // assert
            StringAssert.AreEqualIgnoringCase(sessionKeys.EncryptionKey, expectedKeys.EncryptionKey);
            StringAssert.AreEqualIgnoringCase(sessionKeys.MacKey, expectedKeys.MacKey);
            StringAssert.AreEqualIgnoringCase(sessionKeys.KeyEncryptionKey, expectedKeys.KeyEncryptionKey);
        }

        [TestCaseSource("SessionKeysTestDataAes192And256")]
        public void ShouldCalculateSessionKeysAes192And256(KeySet mainKeys, KeySet expectedKeys)
        {
            // arrange +
            const string hostChallenge = "40C86DD58F3367F2";
            const string cardChallenge = "794521D878979A6B";

            // act
            var mockedKeysProvider = Substitute.For<IGpMasterKeysProvider>();
            mockedKeysProvider.Provide().Returns(mainKeys);
            var cut = new Scp03SessionKeysProvider(mockedKeysProvider, new List<IMacProvider>() { new AesCmacProvider() });
            var sessionKeys = cut.CalculateSessionKeys(hostChallenge, cardChallenge);

            // assert
            StringAssert.AreEqualIgnoringCase(sessionKeys.EncryptionKey, expectedKeys.EncryptionKey);
            StringAssert.AreEqualIgnoringCase(sessionKeys.MacKey, expectedKeys.MacKey);
            StringAssert.AreEqualIgnoringCase(sessionKeys.KeyEncryptionKey, expectedKeys.KeyEncryptionKey);
        }

        public static IEnumerable<TestCaseData> SessionKeysTestDataAes128
        {
            get
            {
                yield return new TestCaseData(
                   new GpTransportKeysProvider2().Provide(),
                   new KeySet()
                   {
                       EncryptionKey = "8e8fd09895792bc0b6f01d1107580a51",
                       KeyEncryptionKey = "707172737475767778797A7B7C7D7E7F",
                       MacKey = "3bdfa3d50b6af293457a15f382954443"
                   });
            }
        }

        public static IEnumerable<TestCaseData> SessionKeysTestDataAes192And256
        {
            get
            {
                yield return new TestCaseData(
                   new GpTransportKeysProviderAes256().Provide(),
                   new KeySet()
                   {
                       EncryptionKey = "35ff7a3f264e1da44e104d815be76cfa8b3f6711d6a98196563840887225f429",
                       KeyEncryptionKey = "404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f",
                       MacKey = "17a8eaa651fad017afbcc5277458a78d97f09893dbbf8e278c793e34b9ecd760"
                   });

                yield return new TestCaseData(
                   new GpTransportKeysProviderAes192().Provide(),
                   new KeySet()
                   {
                       EncryptionKey = "db83eb14041d799c2ff09f288ddd56b31041011a21b00f98",
                       KeyEncryptionKey = "404142434445464748494a4b4c4d4e4f4041424344454647",
                       MacKey = "d66db99888f97d67a088e004fb6a314b0fd57aa191758e37"
                   });
            }
        }
    }
}