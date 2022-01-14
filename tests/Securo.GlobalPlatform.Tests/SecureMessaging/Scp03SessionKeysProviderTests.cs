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
        [TestCaseSource("SessionKeysTestData")]
        public void ShouldCalculateSessionKeys(KeySet mainKeys, KeySet expectedKeys)
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

        public static IEnumerable<TestCaseData> SessionKeysTestData
        {
            get
            {
                // static keys, expected keys, sequence counter
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
    }
}