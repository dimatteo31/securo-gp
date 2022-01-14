using NUnit.Framework;

namespace Securo.GlobalPlatform.SecureMessaging.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03Level3PayloadBuilderTests
    {
        [TestCase("2BD268BD98644FC571909ADB1C06044E", "80F22002024F0000", "84F22002102BD268BD98644FC571909ADB1C06044E")]
        public void BuildPayloadTest(string encPayload, string command, string expectedPayload)
        {
            // arrange
            var cut = new Scp03Level3PayloadBuilder();

            // act 
            var payload = cut.BuildPayload(encPayload, command);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedPayload, payload);
        }
    }
}