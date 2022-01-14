using NUnit.Framework;

namespace Securo.GlobalPlatform.SecureMessaging.Tests.SecureMessaging
{
    [TestFixture()]
    public class Scp03Level1PayloadBuilderTests
    {
        [TestCase("00000000000000000000000000000000", "8082010008C035A7774D4C48EE", "000000000000000000000000000000008482010010c035a7774d4c48ee")]
        [TestCase("00000000000000000000000000000000", "0082010008C035A7774D4C48EE", "000000000000000000000000000000000482010010c035a7774d4c48ee")]
        public void ShouldBuildPayloadTest(string iv, string command, string expectedPayload)
        {
            // arrange
            var cut = new Scp03Level1PayloadBuilder();

            // act 
            var payload = cut.BuildPayload(iv, command);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedPayload, payload);
        }
    }
}