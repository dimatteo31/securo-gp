using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp02SessionKeysProvider : IScp02SessionKeysProvider
    {
        private const string SkEncConst = "0182";
        private const string SkMacConst = "0101";
        private const string SkDekConst = "0181";
        private const string Zeros = "000000000000000000000000";
        private const string Iv = "0000000000000000";

        private readonly ICryptoProvider cryptoProvider;
        private readonly IGpMasterKeysProvider keysProvider;

        public Scp02SessionKeysProvider(IGpMasterKeysProvider keysProvider, IEnumerable<ICryptoProvider> cryptoProvider)
        {
            this.cryptoProvider = cryptoProvider.Single(x => x.Name == CryptoProvider.TrippleDes);
            this.keysProvider = keysProvider;
        }

        public KeySet CalculateSessionKeys(string counter)
        {
            var masterKeySet = this.keysProvider.Provide();
            return new KeySet()
            {
                EncryptionKey = this.GenerateSessionKey(SkEncConst, counter, masterKeySet.EncryptionKey),
                MacKey = this.GenerateSessionKey(SkMacConst, counter, masterKeySet.MacKey),
                KeyEncryptionKey = this.GenerateSessionKey(SkDekConst, counter, masterKeySet.KeyEncryptionKey)
            };
        }

        private string GenerateSessionKey(string constant, string counter, string key)
        {
            var input = $"{constant}{counter}{Zeros}";
            return this.cryptoProvider.Encrypt(Iv, key, input);
        }
    }
}