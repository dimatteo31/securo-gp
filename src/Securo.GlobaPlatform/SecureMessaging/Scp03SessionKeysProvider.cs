using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public partial class Scp03SessionKeysProvider : IScp03SessionKeysProvider
    {
        private const int AesKeySize = 128;
        private readonly IEnumerable<IMacProvider> macProviders;
        private readonly IGpMasterKeysProvider keysProvider;

        public Scp03SessionKeysProvider(IGpMasterKeysProvider keysProvider, IEnumerable<IMacProvider> macProviders)
        {
            this.macProviders = macProviders;
            this.keysProvider = keysProvider;
        }

        public KeySet CalculateSessionKeys(string hostChallenge, string cardChallenge)
        {
            return new KeySet()
            {
                EncryptionKey = this.CalculateSessionKey(SessionKeyType.SEnc, keysProvider.Provide().EncryptionKey, hostChallenge, cardChallenge),
                MacKey = this.CalculateSessionKey(SessionKeyType.SMac, keysProvider.Provide().MacKey, hostChallenge, cardChallenge),
                KeyEncryptionKey = keysProvider.Provide().KeyEncryptionKey,
                RmacKey = this.CalculateSessionKey(SessionKeyType.SRmac, keysProvider.Provide().MacKey, hostChallenge, cardChallenge)
            };
        }

        private string CalculateSessionKey(SessionKeyType sessionKeyType, string key, string hostChallenge, string cardChallenge)
        {
            if (key.Length / 2 != AesKeySize/8)
            {
                throw new InvalidOperationException($"Key size { key.Length / 2 } not supported");
            }

            var input = "0000000000000000000000";
            input += ((byte)sessionKeyType).ToString("X2");
            input += "00";
            input += "0080";
            input += "01";
            input += $"{hostChallenge}{cardChallenge}";
            var provider = this.macProviders.Single(x => x.Name == MacProvider.AesCmacProvider);
            return provider.Generate(string.Empty, key, input);
        }
    }
}