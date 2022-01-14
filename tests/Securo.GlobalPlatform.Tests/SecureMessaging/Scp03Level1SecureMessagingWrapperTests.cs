using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using NUnit.Framework;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.SecureMessaging.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03Level1SecureMessagingWrapperTests
    {
        [Test()]
        public void ShouldWrapScp03Level1SecureMessagingWrapper()
        {
            // arrange
            const string command = "80F22002024F0000";
            const string expectedWarppedCommand = "84F220020A4F002860BEEA93E3CBDC00";
            const string expectedMac = "2860beea93e3cbdce3fea8a7817cf625";
            const string ivMac = "bb426d481a0c3326eaf85393884b22f5";
            const string key = "f91be0b80117f6bbb35e68d352f5a6f6";
            var macProviders = new List<IMacProvider>() { new AesCmacProvider() };
            var cut = new Scp03Level1SecureMessagingWrapper(macProviders);

            // act 
            cut.SetUp(ivMac, key);
            var wrappedCommand = cut.Wrap(command);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedWarppedCommand, wrappedCommand);
            StringAssert.AreEqualIgnoringCase(expectedMac, cut.MacIv);
        }
    }
}