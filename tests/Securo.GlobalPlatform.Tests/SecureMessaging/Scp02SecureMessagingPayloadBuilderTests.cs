using NUnit.Framework;
using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.SecureMessaging.Tests
{
    [TestFixture()]
    public class Scp02SecureMessagingPayloadBuilderTests
    {
        [TestCase("80F22002024F0000", "4F00800000000000", SecureMessagingMode.Level3)]
        [TestCase("80F22002024F0000", "84F220020A4F00", SecureMessagingMode.Level1)]
        public void ShouldFormatCommandPayload(string apduCommand, string payload, SecureMessagingMode secureMessagingMode)
        {
            // arrange 
            var commandParser = new CommandParser();
            var cut = new Scp02SecureMessagingPayloadBuilder(commandParser);

            // act
            var output = cut.Format(secureMessagingMode, commandParser.Parse(apduCommand));

            // assert
            StringAssert.AreEqualIgnoringCase(payload, output);
        }
    }
}