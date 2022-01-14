using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;

namespace Securo.GlobalPlatform.Cryptography
{
    public class TrippleDesCryptoProvider : ICryptoProvider
    {
        private readonly IBufferedCipher bufferedCipher;

        public CryptoProvider Name => CryptoProvider.TrippleDes;

        public TrippleDesCryptoProvider()
        {
            this.bufferedCipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        }

        public string Encrypt(string iv, string key, string input)
        {
            var keyParams = new KeyParameter(Hex.Decode(key));
            this.bufferedCipher.Init(true, keyParams);
            var inputHex = Hex.Decode(input);
            return Hex.ToHexString(bufferedCipher.DoFinal(inputHex));
        }

        public string Decrypt(string iv, string key, string input)
        {
            throw new NotImplementedException();
        }
    }
}