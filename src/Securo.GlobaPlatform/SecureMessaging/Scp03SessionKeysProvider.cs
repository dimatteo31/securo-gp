﻿using Org.BouncyCastle.Crypto.Parameters;
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
            var keySizeInBits = ((key.Length / 2) * 8);
            var keySizeHex = keySizeInBits.ToString("X4");
            var input = "0000000000000000000000";
            input += ((byte)sessionKeyType).ToString("X2");
            input += "00";
            input += keySizeHex;
            var provider = this.macProviders.Single(x => x.Name == MacProvider.AesCmacProvider);
            if (keySizeInBits > AesKeySize)
            {
                var input01 = input + $"01{hostChallenge}{cardChallenge}";
                var input02 = input + $"02{hostChallenge}{cardChallenge}";
                var sessionKey = provider.Generate(string.Empty, key, input01);
                sessionKey += provider.Generate(string.Empty, key, input02);
                return sessionKey.Substring(0, 2* keySizeInBits/8);
            }
            else
            {
                input += $"01{hostChallenge}{cardChallenge}";
                return provider.Generate(string.Empty, key, input);
            }
        }
    }
}