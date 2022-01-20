using NUnit.Framework;
using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using Securo.GlobalPlatform.Tests.TestData;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03PseudoRandomCalculatorTests
    {
        [Test]
        public void ShouldGeneratePseudoRandom()
        {
            // arrange
            const string aid = "A000000151000000";
            const string sequenceCoutner = "00000E";
            const string key = "404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f";
            const string expectedCardRandom = "0A1D17F6856F7EFC";

            // act
            var generator = new Scp03PseudoRandomCalculator(new List<IMacProvider>() { new AesCmacProvider() });
            var random = generator.Generate(key, sequenceCoutner, aid);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCardRandom, random);
        }

        [Test]
        public void ShouldGenerateApduScript()
        {
            // arrange
            const string aid = "A000000151000000";
            const string sequenceCoutner = "00000E";
            const string key = "404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f";
            const string expectedCardRandom = "0A1D17F6856F7EFC";
            const string hostChallenge = "AECA2F67DBAAE340";
            const string expectedExternalAuthenticateWrapped = "84823300105984A45B573C5A748BDDC72592BB41D6";
            var macProviders = new List<IMacProvider>() { new AesCmacProvider() };
            var cryptoProviders = new List<ICryptoProvider>() { new AesCbcProvider() };
            var scp03SessionKeysProvider = new Scp03SessionKeysProvider(new GpTransportKeysProviderAes256(), macProviders);
            var cut = new Scp03SecureContextProvider(macProviders, cryptoProviders, scp03SessionKeysProvider);
            var generator = new Scp03PseudoRandomCalculator(new List<IMacProvider>() { new AesCmacProvider() });
            var initializeUpdate = $"8050000008{hostChallenge}00";
            const string expectedInitializeUpdate = "8050000008AECA2F67DBAAE34000";
            const string commandToWrap = "80F22002024F0000";
            const string expectedGetStatusWrapped = "84F2200218F55B6CE501DC96B36D6CE334B973D712C7B48C9D1447105100";

            // act
            var cardPseudoRandom = generator.Generate(key, sequenceCoutner, aid);
            cut.InitializeSecureContext(new SecureSessionDetails()
            {
                HostChallenge = hostChallenge,
                CardChallenge = cardPseudoRandom,
                CardCryptogram = "d63933f9a779fb37"
            });

            var hostCryptogram = cut.CalculateHostCrypogram().Result;
            var externalAuthenticate = $"8082330008{hostCryptogram}";
            var externalAuthenticateWrapped = cut.Wrap(SecurityLevel.Mac, externalAuthenticate).Result;
            var getStatusWrapped = cut.Wrap(SecurityLevel.Mac_Enc_REnc_RMac, commandToWrap).Result;
           
            // assert
            StringAssert.AreEqualIgnoringCase(expectedCardRandom, cardPseudoRandom);
            StringAssert.AreEqualIgnoringCase(expectedInitializeUpdate, initializeUpdate);
            StringAssert.AreEqualIgnoringCase(expectedExternalAuthenticateWrapped, externalAuthenticateWrapped);
            StringAssert.AreEqualIgnoringCase(expectedGetStatusWrapped, getStatusWrapped);
        }
    }
}