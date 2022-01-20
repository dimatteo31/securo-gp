using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using System;

namespace Securo.GlobalPlatform
{
    public class CardManager : ICardManager
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
       
        private readonly IApduTransmit apduTransmit;
        private readonly ISecureSessionDetailsCreator secureSessionDetailsCreator;
        private readonly IScpInfoProvider scpInfoProvider;
        private readonly ICardResponseParser cardResponseParser;
        private readonly ISecureContextProviderFactory secureContextProviderFactory;
        private ISecureContextProvider secureContextProvider;
        private IAuthenticationCryptogramProvider<Scp03CardAuthenticationCryptogramData> cardAuthenticationCryptogramProvider;

        private ScpInfo ScpInfo { get; set; }
        public SecureSessionDetails SecureSessionDetails { get; private set; }
        public string Aid { get; private set; }

        const string GetDataApdu = "80CA006600";

        public CardManager(
          IApduTransmit apduTransmit,
          IGpMasterKeysProvider gpMasterKeysProvider)
        {
            this.apduTransmit = apduTransmit;
            this.secureSessionDetailsCreator = new SecureSessionDetailsCreator();
            this.scpInfoProvider = new ScpInfoProvider();
            this.cardResponseParser = new CardResponseParser();
            this.secureContextProviderFactory = new SecureContextProviderFactory(gpMasterKeysProvider);
        }

        public void Select(string aid)
        {
            var selectCommand = new SelectApduCommand(0x04, 0x00, aid).Build();
            var cardResponse = apduTransmit.Send(selectCommand);
            if (cardResponse.StatusWord == 0x9000)
            {
                this.Aid = aid;
                var cardRecogntionData = apduTransmit.Send(GetDataApdu);
                if (cardRecogntionData.StatusWord == 0x9000)
                {
                    this.ScpInfo = this.scpInfoProvider.Provide(Hex.Decode(cardRecogntionData.Data));
                }
                else
                {
                    throw new InvalidOperationException("Can't perform Get Data command");
                }
            }
            else
            {
                throw new InvalidOperationException($"Applet not found: {aid}");
            }
        }

        public void InitializeUpdate(byte keySetVersion, byte keyIdentifier, string hostChallenge)
        {
            var command = new InitalizeUpdateCommand(keySetVersion, keyIdentifier, hostChallenge).Build();
            var cardResponse = this.apduTransmit.Send(command);
            if (cardResponse.StatusWord == 0x9000)
            {
                this.SecureSessionDetails = this.secureSessionDetailsCreator.Create(cardResponse.Data);
                this.SecureSessionDetails.HostChallenge = hostChallenge;
                this.SecureSessionDetails.ScpInfo = this.ScpInfo;
                this.secureContextProvider = this.secureContextProviderFactory
                    .Provide((ScpMode)this.SecureSessionDetails.ScpInfo.ScpIdentifier);
                this.secureContextProvider.InitializeSecureContext(this.SecureSessionDetails);
            }
            else
            {
                throw new InvalidOperationException($"Error in InitializeUpdate: SW={cardResponse.StatusWord.ToString("X2")}");
            }
        }

        public void ExternalAuthenticate(SecurityLevel securityLevel)
        {
            var hostAuthCryptogram = this.secureContextProvider.CalculateHostCrypogram().Result;
            var command = new ExternalAuthenticateCommand((byte)securityLevel, hostAuthCryptogram).Build();
            var wrappedCommand = this.secureContextProvider.Wrap(SecurityLevel.Mac, command).Result;
            var cardResponse = this.apduTransmit.Send(wrappedCommand);
            if (cardResponse.StatusWord != 0x9000)
            {
                throw new InvalidOperationException($"Error in ExternalAuthenticate: SW={cardResponse.StatusWord.ToString("X2")}");    
            }
        }

        public void StoreData(string data)
        {
            var command = new StoreDataCommand(0x00, 0x00, data).Build();
            var wrappedCommand = this.secureContextProvider.Wrap(SecurityLevel.Mac, command).Result;
            var cardResponse = this.apduTransmit.Send(wrappedCommand);
            if (cardResponse.StatusWord != 0x9000)
            {
                throw new InvalidOperationException($"Error in StoreData: SW={cardResponse.StatusWord.ToString("X2")}");
            }
        }

        public string GetData(byte tagMsb, byte tagLsb)
        {
            throw new NotImplementedException();
        }

        public CardResponse TransmitApdu(SecurityLevel securityLevel, string command)
        {
            log.Info($"TX-Plain -> {command}");
            var wrappedCommand = this.secureContextProvider.Wrap(securityLevel, command).Result;
            var cardResponse = this.apduTransmit.Send(wrappedCommand);
            if (cardResponse.StatusWord != 0x9000)
            {
                throw new InvalidOperationException($"Error in TransmitApdu: SW={cardResponse.StatusWord.ToString("X2")}");
            }
            else
            {
                var unwrappedResponse = this.secureContextProvider.Unwrap(securityLevel, cardResponse.FullResponse).Result.ToUpper();
                log.Info($"RX-Plain -> {unwrappedResponse}");
                return this.cardResponseParser.Parse(unwrappedResponse);
            }
        }
    }
}