using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;
using Securo.GlobalPlatform.Tests.TestData;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    // integration test
    class Scp02SecureContextProviderTests
    {
        private readonly IEnumerable<IMacProvider> retailMacs;
        private readonly IEnumerable<ICryptoProvider> cryptoProviders;
        private readonly IScp02SessionKeysProvider scp02SessionKeysProvider;
        
        private ISecureContextProvider cut;

        public Scp02SecureContextProviderTests()
        {
            retailMacs = new List<IMacProvider>() { new SecureMessagingMacProvider(), new RetailMacProvider() };
            cryptoProviders = new List<ICryptoProvider>() { new TrippleDesCryptoProvider(), new SingleDesProvider() };
            scp02SessionKeysProvider = new Scp02SessionKeysProvider(new GpTransportKeysProvider(), cryptoProviders);
            cut = new Scp02SecureContextProvider(retailMacs, cryptoProviders, scp02SessionKeysProvider);
        }

        [Test]
        public void ShouldWrapSingleCommandInMacMode()
        {
            // arrange
            const string command = "80820100081B6AEFE95EDC1391";
            const string expectedCommand = "84820100101B6AEFE95EDC1391CDB05F3704826A09";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "4F90E63D68B2FA45",
                CardChallenge = "5C1F9C9B003A",
                SequenceCounter = "0038",
                ScpInfo = new ScpInfo() { ImplementationOptions = 0x15, ScpIdentifier = 0x02}
            });

            var wrappedCommand = cut.Wrap(SecurityLevel.Mac, command).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand, wrappedCommand);
        }

        [Test]
        public void ShouldWrapTwoCommandsInMacMode()
        {
            // arrange
            const string command1 = "80820100081B6AEFE95EDC1391";
            const string command2 = "80F22002024F0000";
            const string expectedCommand1 = "84820100101B6AEFE95EDC1391CDB05F3704826A09";
            const string expectedCommand2 = "84F220020A4F00A2F5A3EC2B0E98AA00";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "4F90E63D68B2FA45",
                CardChallenge = "5C1F9C9B003A",
                SequenceCounter = "0038",
                ScpInfo = new ScpInfo() { ImplementationOptions = 0x15, ScpIdentifier = 0x02 }
            });

            var wrappedCommand1 = cut.Wrap(SecurityLevel.Mac, command1).Result;
            var wrappedCommand2 = cut.Wrap(SecurityLevel.Mac, command2).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand1, wrappedCommand1);
            StringAssert.AreEqualIgnoringCase(expectedCommand2, wrappedCommand2);
        }

        [Test]
        public void ShouldWrapTwoCommandsInEncMacMode()
        {
            // arrange
            const string command1 = "80820300081E043AEF7B01F064";
            const string expectedCommand1 = "84820300101E043AEF7B01F064A3C6D1A7363A713C";
            const string command2 = "80F21002024F0000";
            const string expectedCommand2 = "84F210021047C7B7B38890C89DFD47AC8726DF00A000";
            const string command3 = "80F22002024F0000";
            const string expectedCommand3 = "84F220021047C7B7B38890C89D90AC08C89212A59200";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "63EA86275F44443C",
                CardChallenge = "D46349081C02",
                SequenceCounter = "0040",
                ScpInfo = new ScpInfo() { ImplementationOptions = 0x15, ScpIdentifier = 0x02 }
            });

            var wrappedCommand1 = cut.Wrap(SecurityLevel.Mac, command1).Result;
            var wrappedCommand2 = cut.Wrap(SecurityLevel.Mac_Enc, command2).Result;
            var wrappedCommand3 = cut.Wrap(SecurityLevel.Mac_Enc, command3).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand1, wrappedCommand1);
            StringAssert.AreEqualIgnoringCase(expectedCommand2, wrappedCommand2);
            StringAssert.AreEqualIgnoringCase(expectedCommand3, wrappedCommand3);
        }
    }
}