using NUnit.Framework;

namespace Securo.GlobalPlatform.Model.Tests
{
    [TestFixture()]
    public class CardResponseParserTests
    {
        [TestCase("00009000", "0000", 0x9000)]
        [TestCase("9000", "", 0x9000)]
        [TestCase("90009000", "9000", 0x9000)]
        public void ShouldParseCardResponse(string fullResponse, string data, int statusWord)
        {
            // arrange
            // act
            var parser = new CardResponseParser();
            var result = parser.Parse(fullResponse);

            // assert
            Assert.AreEqual(data, result.Data);
            Assert.AreEqual(statusWord, result.StatusWord);
            Assert.AreEqual(fullResponse, result.FullResponse);
        }
    }
}