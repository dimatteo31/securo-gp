using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Model;
using NUnit.Framework;
using Org.BouncyCastle.Utilities.Encoders;

namespace Securo.GlobalPlatform.Tests.Commands
{
    class CommandParserTests
    {
        [Test]
        public void ShouldParseCommandWithLe()
        {
            // arrange
            var data = "1122334455";
            var command = $"00a4040005{data}01";
            var cut = new CommandParser();

            // act
            var parsedCommand = cut.Parse(command);

            // assert
            Assert.AreEqual(parsedCommand.Le, 0x01);
            Assert.AreEqual(parsedCommand.HasLe, true);
            Assert.AreEqual(Hex.ToHexString(parsedCommand.Data), data);
        }

        [Test]
        public void ShouldParseCommandWithoutLe()
        {
            // arrange
            var data = "1122334455";
            var command = $"00a4040005{data}";
            var cut = new CommandParser();

            // act
            var parsedCommand = cut.Parse(command);

            // assert
            Assert.AreEqual(parsedCommand.Le, 0x00);
            Assert.AreEqual(parsedCommand.HasLe, false);
            Assert.AreEqual(Hex.ToHexString(parsedCommand.Data), data);
        }

        [TestCase("00a4040005112233445500", "1122334455", true)]
        [TestCase("00a40400051122334455", "1122334455", false)]
        public void ShouldBuildCommand(string expectedCommand, string data, bool hasLe)
        {
            // arrange
            var dataHex = Hex.Decode(data);
            var command = new ApduCommand()
            {
                Class = 0x00,
                Instruction = 0xA4,
                P1 = 0x04,
                P2 = 0x00,
                Lc = (byte)dataHex.Length,
                Data = dataHex,
                Le = 0x00,
                HasLe = hasLe
            }; 
            var cut = new CommandParser();

            // act
            var builtCommand = cut.Build(command);

            // assert
            StringAssert.AreEqualIgnoringCase(expectedCommand, builtCommand);
        }
    }
}
