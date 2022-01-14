using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Securo.GlobalPlatform.Cryptography
{
    public class RetailMacProvider : IMacProvider
    {
        private const int MacSizeBits = 64;
        private readonly IMac macProvider;
        public MacProvider Name => MacProvider.Retail;

        public RetailMacProvider()
        {
            this.macProvider = new CbcBlockCipherMac(new DesEdeEngine(), MacSizeBits, new ISO7816d4Padding());
        }

        public string Generate(string iv, string key, string input)
        {
            this.macProvider.Init(new ParametersWithIV(new KeyParameter(Hex.Decode(key)), Hex.Decode(iv)));
            var inputHex = Hex.Decode(input);
            this.macProvider.BlockUpdate(inputHex, 0, inputHex.Length);
            var output = new byte[MacSizeBits/8];
            this.macProvider.DoFinal(output, 0);
            return Hex.ToHexString(output);
        }
    }
}