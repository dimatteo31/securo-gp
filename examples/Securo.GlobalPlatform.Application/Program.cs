using Org.BouncyCastle.Utilities.Encoders;
using System;

[assembly: log4net.Config.XmlConfigurator(ConfigFile = "log4net.config", Watch = true)]

namespace Securo.GlobalPlatform.Application
{
    class Program
    {
        private static string PcscReader = "Broadcom Corp Contacted SmartCard 0";
        private static string AidGp21 = "A000000003000000";
        private static string AidGp22 = "A000000151000000";

        static void Main(string[] args)
        {
            var reader = new PcscReader();
            reader.Connect(PcscReader);
            var cardManager = new CardManager(reader, new GpTransportKeysProvider());
            cardManager.Select(AidGp21);
            byte keyId = 0x00;
            byte keySetVersion = 0x00;
            var random = new byte[8];
            new Random().NextBytes(random);
            cardManager.InitializeUpdate(keySetVersion, keyId, Hex.ToHexString(random));
            var scp = Model.SecurityLevel.None;
            cardManager.ExternalAuthenticate(scp);
            var getStatusCommand = "80F21002024F0000";
            var resp = cardManager.TransmitApdu(scp, getStatusCommand);
            resp = cardManager.TransmitApdu(scp, "80F24002024F0000");
        }
    }
}
