using NUnit.Framework;
using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using System.Linq;

namespace Securo.GlobalPlatform.Tests
{
    [TestFixture()]
    public class ScpInfoProvider2Tests
    {
        [TestCase("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040105650B06092B8510864864020103660C060A2B060104012A026E0102",
            0x01, 0x05)]
        [TestCase("663f733d06072a864886fc6b01600c060a2a864886fc6b02020201630906072a864886fc6b03640b06092a864886fc6b040360660c060a2b060104012a026e0102",
            0x03, 0x60)]
        [TestCase("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102",
            0x02, 0x15)]
        public void ShouldProvideScpInfo(string cardRecognitionData, byte scpIdentifier, byte scpImplementationOption)
        {
            // arrange
            var expected = new ScpInfo() { ScpIdentifier = scpIdentifier, ImplementationOptions = scpImplementationOption };
           
            // act
            var scpInfoProvider = new ScpInfoProvider();
            var provided = scpInfoProvider.Provide(Hex.Decode(cardRecognitionData));

            // assert
            Assert.AreEqual(expected.ScpIdentifier, provided.ScpIdentifier);
            Assert.AreEqual(expected.ImplementationOptions, provided.ImplementationOptions);
        }
    }
}