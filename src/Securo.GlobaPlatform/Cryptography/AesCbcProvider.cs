using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Securo.GlobalPlatform.Cryptography
{
    public class AesCbcProvider : ICryptoProvider
    {
        public CryptoProvider Name => CryptoProvider.AesCbc;

        public string Decrypt(string iv, string key, string cryptogram)
        {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new ISO7816d4Padding());
            cipher.Init(false, new ParametersWithIV(new KeyParameter(Hex.Decode(key)), Hex.Decode(iv)));
            return Hex.ToHexString(cipher.DoFinal(Hex.Decode(cryptogram)));
        }

        public string Encrypt(string iv, string key, string input)
        {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new ISO7816d4Padding());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(Hex.Decode(key)), Hex.Decode(iv)));
            return Hex.ToHexString(cipher.DoFinal(Hex.Decode(input)));
        }
    }
}