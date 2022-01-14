using NUnit.Framework;
using System.Collections.Generic;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Cryptography;

namespace Securo.GlobalPlatform.SecureMessaging.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03Level3SecureMessagingWrapperTests
    {
        [Test()]
        public void ShouldWrapScp03Level3SecureMessagingWrapper()
        {
            const string command = "80F22002024F0000";
            const string expectedCommand = "80F22002102BD268BD98644FC571909ADB1C06044E00";
            const string ivEnc = "00000000000000000000000000000000";
            const string keyEnc = "7e50526a3f64b6fea6018dc752b5c7ae";
            var counter = 0x1;

            var cryptoProviders = new List<ICryptoProvider>() { new AesCbcProvider() };
            var cut = new Scp03Level3SecureMessagingWrapper(cryptoProviders);

            // act 
            cut.SetUp(ivEnc, keyEnc, counter);
            var wrappedCommand = cut.Wrap(command);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand, wrappedCommand);
        }
    }
}