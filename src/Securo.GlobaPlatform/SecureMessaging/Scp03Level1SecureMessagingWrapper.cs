using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03Level1SecureMessagingWrapper : IScp03Level1SecureMessagingWrapper
    {
        private int CmacSize = 8;
        const int RmacSizeInBytes = 8;
        private readonly IScp03PayloadBuilder payloadBuilder;
        private readonly IEnumerable<IMacProvider> macProviders;
        private readonly ICommandParser commandParser;

        public SecurityLevel SecurityLevel =>  SecurityLevel.Mac;
        public string MacIv { get; private set; }

        private string iv;
        private string key;

        public Scp03Level1SecureMessagingWrapper(IEnumerable<IMacProvider> macProviders)
        {
            this.macProviders = macProviders;
            this.payloadBuilder = new Scp03Level1PayloadBuilder();
            this.commandParser = new CommandParser();
        }

        public void SetUp(string iv, string key)
        {
            this.iv = iv;
            this.key = key;
        }

        public string Wrap(string command)
        {
            var scp03Level1Payload = payloadBuilder.BuildPayload(this.iv, command);
            this.MacIv =
                this.macProviders.Single(x => x.Name == Enums.MacProvider.AesCmacProvider).Generate(string.Empty, this.key, scp03Level1Payload);
            var cmac = this.MacIv.Substring(0, CmacSize * 2);
            return UpdateData(command, cmac);
        }

        public string Unwrap(string response)
        {
            var commandParser = new CardResponseParser();
            var apduResponse = commandParser.Parse(response);
            var responseData = apduResponse.Data.Substring(0, apduResponse.Data.Length - RmacSizeInBytes * 2);
            var responseRmac = apduResponse.Data.Substring(apduResponse.Data.Length - RmacSizeInBytes*2, RmacSizeInBytes*2);
            var payloadForRmac = $"{iv}{responseData}{apduResponse.StatusWord.ToString("X4")}";
            var macProvider = this.macProviders.Single(x => x.Name == Enums.MacProvider.AesCmacProvider);
            var rmac = macProvider.Generate(this.MacIv, this.key, payloadForRmac).Substring(0, RmacSizeInBytes*2);
            if (String.Compare(responseRmac.ToLower(), rmac.ToLower()) != 0)
            {
                throw new InvalidOperationException("Invalid RMAC in response!");
            }

            return responseData + apduResponse.StatusWord.ToString("X4");
        }

        private string UpdateData(string command, string data)
        {
            var p = this.commandParser.Parse(command);
            p.Class |= 0x04;
            p.Lc += (byte)Hex.Decode(data).Length;
            p.Data = p.Data.Concat(Hex.Decode(data)).ToArray();
            return this.commandParser.Build(p);
        }
    }
}