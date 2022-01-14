using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;

namespace Securo.GlobalPlatform.Cryptography
{
    public class AesCmacProvider : IMacProvider
    {
        private const int AesKeySizeBits = 128;
        private const int MacSizeBits = 128;
        public MacProvider Name => MacProvider.AesCmacProvider;

        public string Generate(string iv, string key, string input)
        {
            var mac = new CMac(new AesEngine(), AesKeySizeBits);
            mac.Init(new KeyParameter(Hex.Decode(key)));
            var inputHex = Hex.Decode(input);
            mac.BlockUpdate(inputHex, 0, inputHex.Length);
            var outBytes = new byte[MacSizeBits / 8];
            mac.DoFinal(outBytes, 0);
            return Hex.ToHexString(outBytes.Take(MacSizeBits / 8).ToArray());
        }
    }
}