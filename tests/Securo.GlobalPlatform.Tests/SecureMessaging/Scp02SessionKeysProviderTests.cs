using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;
using Securo.GlobalPlatform.Tests.TestData;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    public partial class Scp02SessionKeysProviderTests
    {
        private IGpMasterKeysProvider gpMasterKeysProvider;

        [TestCaseSource("SessionKeysTestData")]
        public void ShouldCalculateSessionKeys(KeySet staticKeys, KeySet expectedKeys, string sequenceCounter)
        {
            // arrange & act
            gpMasterKeysProvider = new GpTransportKeysProvider();
            var cut = new Scp02SessionKeysProvider(gpMasterKeysProvider, new List<ICryptoProvider> { new TrippleDesCryptoProvider() });
            var sessionKeys = cut.CalculateSessionKeys(sequenceCounter);

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
                    new GpTransportKeysProvider().Provide(),
                    new KeySet()
                    {
                        EncryptionKey = "56a1dc0a4b4165c9ed464fab97380abd",
                        KeyEncryptionKey = "e5eeb4c6878686609a34c2b661183699",
                        MacKey = "6ddcb69848e88f941cdd5978b46b6a3e"
                    },
                    "0017");

                yield return new TestCaseData(
                    new GpTransportKeysProvider().Provide(),
                    new KeySet()
                    {
                        EncryptionKey = "cc603efdad75c26767452b26d56bf45d",
                        KeyEncryptionKey = "fa015b1fec95e127f4865e11bda0bacd",
                        MacKey = "e33a0cb8e497ce5c9f1efa6bdab39b39"
                    },
                    "0027");
            }
        }
    }
}