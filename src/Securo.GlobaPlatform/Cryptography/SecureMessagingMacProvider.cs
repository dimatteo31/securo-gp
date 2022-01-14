using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.SecureMessaging;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;

namespace Securo.GlobalPlatform.Cryptography
{
    public class SecureMessagingMacProvider : IMacProvider
    {
        private const int MacSizeBits = 64;
        private const int BlockSize = 8;
        public MacProvider Name => MacProvider.SecureMessagingMac;

        public string Generate(string ivMac, string key, string input)
        {
            var chunks = input.ApplyPadding(BlockSize).Split(BlockSize).ToArray();
            for (var i = 0; i < chunks.Count() - 1; i++)
            {
                ivMac = EncrpytBlock(false, ivMac, key, Hex.ToHexString(chunks[i]));
            }

            return EncrpytBlock(true, ivMac, key, Hex.ToHexString(chunks.Last()));
        }

        private static string EncrpytBlock(bool isFinal, string ivMac, string key, string input)
        {
            var engine = new DesEngine();
            if (isFinal)
            {
                engine = new DesEdeEngine();
            }

            var macProvider = new CbcBlockCipherMac(engine, MacSizeBits);
            macProvider.Init(new ParametersWithIV(new KeyParameter(Hex.Decode(key)), Hex.Decode(ivMac)));
            macProvider.BlockUpdate(Hex.Decode(input), 0, Hex.Decode(input).Length);
            var output = new byte[MacSizeBits / BlockSize];
            macProvider.DoFinal(output, 0);
            return Hex.ToHexString(output);
        }
    }
}