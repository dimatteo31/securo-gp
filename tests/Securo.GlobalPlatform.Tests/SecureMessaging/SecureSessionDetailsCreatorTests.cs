using NUnit.Framework;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Securo.GlobalPlatform.SecureMessaging.Tests
{
    [TestFixture()]
    public class SecureSessionDetailsCreatorTests
    {
        private ISecureSessionDetailsCreator cut;

        [TestCase("0000417100760397383602020040D46349081C02164BC640D23E80D6", (byte)0x02)]
        [TestCase("00000346020614090044010360C77C60598FC0D3D4F21520D3A7E8CB34", (byte)0x03)]
        public void ShouldCreateSessionDetails(string cardRecognitionData, byte scpMode)
        {
            // arrange
            cut = new SecureSessionDetailsCreator();

            // act
            var result = cut.Create(cardRecognitionData);

            // assert
            Assert.AreEqual(result.ScpInfo.ScpIdentifier, scpMode);
        }
    }
}