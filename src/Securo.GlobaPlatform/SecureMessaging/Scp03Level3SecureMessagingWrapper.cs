using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03Level3SecureMessagingWrapper : IScp03Level3SecureMessagingWrapper
    {
        const int RmacSize = 8;
        const int StatusWordSize = 2;
        const int EncryptedIvSize = 16;

        private readonly IEnumerable<ICryptoProvider> cryptoProviders;
        public string EncryptedIv { get; private set; }
        public SecurityLevel SecurityLevel => SecurityLevel.Mac_Enc;
        
        private string iv;
        private string key;
        private int counter;

        public Scp03Level3SecureMessagingWrapper(
            IEnumerable<ICryptoProvider> cryptoProviders)
        {
            this.cryptoProviders = cryptoProviders;
        }

        public void SetUp(string iv, string key, int counter)
        {
            this.iv = iv;
            this.key = key;
            this.counter = counter;
        }

        public string Wrap(string command)
        {
            this.EncryptedIv = EncryptIcv(false, this.iv, this.key, this.counter).Substring(0, EncryptedIvSize*2);
            var updatedCommandWithEncrpytedData = EncrpytDataAndUpdateCommand(this.EncryptedIv, this.key, command);
            return updatedCommandWithEncrpytedData;
        }

        public string Unwrap(string response)
        {
            var cardResponse = new CardResponseParser();
            var x = cardResponse.Parse(response);
            this.EncryptedIv = EncryptIcv(true, this.iv, this.key, this.counter).Substring(0, EncryptedIvSize*2);
            var encryptedMessage = response.Substring(0, response.Length - RmacSize*2 - StatusWordSize*2);
            var plain = this.cryptoProviders.Single(x => x.Name == Enums.CryptoProvider.AesCbc)
                .Decrypt(this.EncryptedIv, this.key, encryptedMessage);
            return plain + x.StatusWord.ToString("X4");
        }

        private string EncryptIcv(bool isResponseDecrypt, string iv, string encryptionKey, int counter)
        {
            var counterBytes = new byte[12].Concat(BitConverter.GetBytes(counter).Reverse()).ToArray();
            if (isResponseDecrypt)
            {
                counterBytes[0] = 0x80;
            }

            var encryptedData = this.cryptoProviders.Single(x => x.Name == Enums.CryptoProvider.AesCbc)
                .Encrypt(iv, encryptionKey, Hex.ToHexString(counterBytes));
            return encryptedData;
        }

        private string EncrpytDataAndUpdateCommand(string iv, string encryptionKey, string parsedCommand)
        {
            var commandParser = new CommandParser();
            var newApduCommand = commandParser.Parse(parsedCommand);
            var encryptedData = this.cryptoProviders.Single(x => x.Name == Enums.CryptoProvider.AesCbc)
                .Encrypt(iv, encryptionKey, Hex.ToHexString(newApduCommand.Data));
            newApduCommand.Lc = (byte)(encryptedData.Length / 2);
            newApduCommand.Data = Hex.Decode(encryptedData);
            return commandParser.Build(newApduCommand);
        }
    }
}