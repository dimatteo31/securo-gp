using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using NUnit.Framework;
using System.Collections.Generic;
using Securo.GlobalPlatform.Tests.TestData;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03SecureContextProviderTests
    {
        private readonly IEnumerable<IMacProvider> macProviders;
        private readonly IEnumerable<ICryptoProvider> cryptoProviders;
        private readonly IScp03SessionKeysProvider scp03SessionKeysProvider;
        private ISecureContextProvider cut;

        public Scp03SecureContextProviderTests()
        {
            macProviders = new List<IMacProvider>() { new AesCmacProvider() };
            cryptoProviders = new List<ICryptoProvider>() { new AesCbcProvider() };
            scp03SessionKeysProvider = new Scp03SessionKeysProvider(new GpTransportKeysProvider(), macProviders);
            cut = new Scp03SecureContextProvider(macProviders, cryptoProviders, scp03SessionKeysProvider);
        }

        [Test]
        public void ShouldWrapSingleCommandInMacMode()
        {
            // arrange
            const string command = "808201000845E7C2FAABDEEFF2";
            const string expectedCommand = "848201001045E7C2FAABDEEFF285E5D5DFBD0A0FE7";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "A08E3F160A919F31",
                CardChallenge = "F27B765529C7F332",
                CardCryptogram = "0b0324e5fea58468"
            });

            var wrappedCommand = cut.Wrap(SecurityLevel.Mac, command).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand, wrappedCommand);
        }

        [Test]
        public void ShouldWrapTwoCommandsInMacMode()
        {
            // arrange
            const string command1 = "8082010008C035A7774D4C48EE";
            const string expectedCommand1 = "8482010010C035A7774D4C48EEBB426D481A0C3326";
            const string command2 = "80F22002024F0000";
            const string expectedCommand2 = "84F220020A4F002860BEEA93E3CBDC00";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {  
                HostChallenge = "9DB1571B7D76687C",
                CardChallenge = "4990734952AF8D49",
                CardCryptogram = "a917369cbee5d449"
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
            const string command1 = "8082030008259D8F4847515464";
            const string expectedCommand1 = "8482030010259D8F484751546495BBF8EE8DE31F5D";
            const string command2 = "80F22002024F0000";
            const string expectedCommand2 = "84F22002182BD268BD98644FC571909ADB1C06044E98491F0AB2903C9E00";
            const string command3 = "80F22002024F0000";
            const string expectedCommand3 = "84F220021853F1E908B89DEDCD3A2B03235B2DA5F1FFE1C2808F2819DC00";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "09A6876A18A28878",
                CardChallenge = "D16D0B2E63C700D0",
                MacIv = "00000000000000000000000000000000",
                EncryptionIv = "00000000000000000000000000000000",
                IvCounter = 1,
                CardCryptogram = "c31ca1de694d3d08"
            });

            var wrappedCommand1 = cut.Wrap(SecurityLevel.Mac, command1).Result;
            var wrappedCommand2 = cut.Wrap(SecurityLevel.Mac_Enc, command2).Result;
            var wrappedCommand3 = cut.Wrap(SecurityLevel.Mac_Enc, command3).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand1, wrappedCommand1);
            StringAssert.AreEqualIgnoringCase(expectedCommand2, wrappedCommand2);
            StringAssert.AreEqualIgnoringCase(expectedCommand3, wrappedCommand3);
        }

        [Test]
        public void ShouldWrapTwoCommandsInRmacMode()
        {
            // arrange
            const string command1 = "80821100083962B9B10D337B17";
            const string expectedCommand1 = "84821100103962B9B10D337B17E3F6580BF9F4AE62";
            const string command2 = "80F22002024F0000";
            const string expectedCommand2 = "84F220020A4F00C0375B0F0928C6D200";
            const string response2 = "E30D4F07A00000015153509F700101E64A55A6C79EE82F9000";
            const string expectedUnwrappedCommand = "E30D4F07A00000015153509F7001019000";
            
            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "CE39F278E3B1FF0D",
                CardChallenge = "4A38A31EDB10B005",
                MacIv = "00000000000000000000000000000000",
                EncryptionIv = "00000000000000000000000000000000",
                IvCounter = 1,
                CardCryptogram = "40530d0f0d638ac5"
            });

            var wrappedCommand1 = cut.Wrap(SecurityLevel.Mac_RMac, command1).Result;
            var wrappedCommand2 = cut.Wrap(SecurityLevel.Mac_RMac, command2).Result;
            var unwrappedCommand = cut.Unwrap(SecurityLevel.Mac_RMac, response2).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand1, wrappedCommand1);
            StringAssert.AreEqualIgnoringCase(expectedCommand2, wrappedCommand2);
            StringAssert.AreEqualIgnoringCase(expectedUnwrappedCommand, unwrappedCommand);
        }

        [Test]
        public void ShouldUnwrapTwoCommandsInMacEncREncRmacMode()
        {
            // arrange
            const string command1 = "8082330008EAE9727A80E0C4ED";
            const string expectedCommand1 = "8482330010EAE9727A80E0C4ED6FD4D796189BFA61";
            const string command2 = "80F22002024F0000";
            const string expectedCommand2 = "84F22002182E6E5F29A91803C860002029900ADB6B635596FC98472E2B00";
            const string response2 = "E7044E45CF0177E526398B2DD243B6E48E68E4AA466468139000";
            const string expectedUnwrappedCommand = "E30D4F07A00000015153509F7001019000";
            
            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "7E7B7BD6BBACED6B",
                CardChallenge = "DF5BF9B50B977F64",
                MacIv = "00000000000000000000000000000000",
                EncryptionIv = "00000000000000000000000000000000",
                IvCounter = 1,
                CardCryptogram = "d0e982bc2f7192a6"
            });

            var wrappedCommand1 = cut.Wrap(SecurityLevel.Mac, command1).Result;
            var wrappedCommand2 = cut.Wrap(SecurityLevel.Mac_Enc_REnc_RMac, command2).Result;
            var unwrappedCommand = cut.Unwrap(SecurityLevel.Mac_Enc_REnc_RMac, response2).Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand1, wrappedCommand1);
            StringAssert.AreEqualIgnoringCase(expectedCommand2, wrappedCommand2);
            StringAssert.AreEqualIgnoringCase(expectedUnwrappedCommand, unwrappedCommand);
        }


        [Test()]
        public void ShouldCalculateHostCrypogramTest()
        {
            // arrange
            const string expectedCardCryptogram = "EAE9727A80E0C4ED";

            // act
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = "7E7B7BD6BBACED6B",
                CardChallenge = "DF5BF9B50B977F64",
                MacIv = "00000000000000000000000000000000",
                EncryptionIv = "00000000000000000000000000000000",
                IvCounter = 1,
                CardCryptogram = "d0e982bc2f7192a6"
            });

            var cac = cut.CalculateHostCrypogram().Result;

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCardCryptogram, cac);
        }
    }
}