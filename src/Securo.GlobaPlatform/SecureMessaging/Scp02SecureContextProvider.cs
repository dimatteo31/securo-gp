using Securo.GlobalPlatform.Commands;
using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp02SecureContextProvider : ISecureContextProvider
    {
        private readonly ICommandParser commandParser;
        private readonly ISecureMessagingPayloadFormatter secureMessagingPayloadFormatter;
        private readonly IEnumerable<ICryptoProvider> cryptoProviders;
        private readonly IEnumerable<IMacProvider> retailMacs;
        private readonly IAuthenticationCryptogramProvider<Scp02CardAuthenticationCryptogram> cardAuthCrypogramProvider;
        private readonly IAuthenticationCryptogramProvider<Scp02HostAuthenticationCryptogramData> hostAuthCrypogramProvider;
        private readonly IScp02SessionKeysProvider scp02SessionKeysProvider;

        public SecureSessionDetails SecureSessionDetails { get; private set; }

        private const string IvZeros = "0000000000000000";

        public Scp02SecureContextProvider(
            IEnumerable<IMacProvider> retailMacs, 
            IEnumerable<ICryptoProvider> cryptoProviders,
            IScp02SessionKeysProvider scp02SessionKeysProvider)
        {
           
            this.cryptoProviders = cryptoProviders;
            this.retailMacs = retailMacs;
            this.scp02SessionKeysProvider = scp02SessionKeysProvider;
            this.hostAuthCrypogramProvider = new Scp02HostAuthenticationCryptogramProvider(retailMacs);
            this.cardAuthCrypogramProvider = new Scp02CardAuthenticationCryptogramProvider(retailMacs);
            this.commandParser = new CommandParser();
            this.secureMessagingPayloadFormatter = new Scp02SecureMessagingPayloadBuilder(this.commandParser);
        }

        public Task<string> CalculateHostCrypogram()
        {
            return Task.FromResult(this.hostAuthCrypogramProvider.Calculate(this.SecureSessionDetails.SessionKeys.EncryptionKey,
                new Scp02HostAuthenticationCryptogramData()
                {
                    CardChallenge = this.SecureSessionDetails.CardChallenge,
                    Counter = this.SecureSessionDetails.SequenceCounter,
                    HostChallenge = this.SecureSessionDetails.HostChallenge
                }));
        }

        public void InitializeSecureContext(SecureSessionDetails secureSessionDetails)
        {
            this.SecureSessionDetails = secureSessionDetails;
            this.SecureSessionDetails.MacIv = "0000000000000000";

            if (this.SecureSessionDetails.MacIv.Length / 2 != 8)
            {
                throw new InvalidOperationException("Invalid MacIv length (shall be 8 bytes)");
            }

            if (this.SecureSessionDetails.CardChallenge.Length / 2 != 6)
            {
                throw new InvalidOperationException("Invalid CardChallenge length (shall be 6 bytes)");
            }

            if (this.SecureSessionDetails.HostChallenge.Length / 2 != 8)
            {
                throw new InvalidOperationException("Invalid HostChallenge length (shall be 8 bytes)");
            }
            
            this.SecureSessionDetails.SessionKeys = this.scp02SessionKeysProvider.CalculateSessionKeys(this.SecureSessionDetails.SequenceCounter);
        }

        public Task<string> Unwrap(SecurityLevel securityLevel, string command)
        {
            return Task.FromResult(command);
        }

        public Task<string> Wrap(SecurityLevel securityLevel,  string command)
        {
            var apduCommand = this.commandParser.Parse(command);

            switch (securityLevel)
            {
                case SecurityLevel.None:
                    return Task.FromResult(command);

                case SecurityLevel.Mac:
                    var macHex = this.GenerateMac(apduCommand);
                    var cmd = this.BuildCommand(false, apduCommand, macHex);
                    return Task.FromResult(cmd);

                case SecurityLevel.Mac_Enc:
                    macHex = this.GenerateMac(apduCommand);
                    var encryptedData = this.EncryptData(apduCommand);
                    cmd = this.BuildCommand(true, apduCommand, Hex.Decode(encryptedData + Hex.ToHexString(macHex)));
                    return Task.FromResult(cmd);

                default:
                    throw new InvalidOperationException();
            }
        }

        private byte[] GenerateMac(ApduCommand apduCommand)
        {
            var payload = secureMessagingPayloadFormatter.Format(SecureMessagingMode.Level1, apduCommand);
            var macHex = Hex.Decode(this.retailMacs.Single(x => x.Name == MacProvider.SecureMessagingMac).Generate( this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.MacKey, payload));
            switch (this.SecureSessionDetails.ScpInfo.ImplementationOptions)
            {
                case (byte)Scp02Configuration.IcvEncryption_TrueRandom:
                case (byte)Scp02Configuration.IcvEncryption_PseudoRandom:
                    this.SecureSessionDetails.MacIv = this.cryptoProviders.Single(x => x.Name == CryptoProvider.SingleDes).
                        Encrypt(IvZeros, this.SecureSessionDetails.SessionKeys.MacKey.Substring(0, 16), Hex.ToHexString(macHex));
                    break;
            }

            return macHex;
        }

        private string EncryptData(ApduCommand apduCommand)
        {
            var paddedData = this.secureMessagingPayloadFormatter.Format(SecureMessagingMode.Level3, apduCommand);
            return this.cryptoProviders.Single(x => x.Name == CryptoProvider.TrippleDes).Encrypt(this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.EncryptionKey, paddedData);
        }

        private string BuildCommand(bool isLevel3, ApduCommand apduCommand, byte[] data)
        {
            if (!isLevel3)
            {
                return this.commandParser.Build(
                    new ApduCommand()
                    {
                        Class = (byte)(apduCommand.Class | 0x04),
                        Instruction = apduCommand.Instruction,
                        P1 = apduCommand.P1,
                        P2 = apduCommand.P2,
                        Lc = (byte)(apduCommand.Lc + data.Length),
                        Data = apduCommand.Data.Concat(data).ToArray(),
                        Le = apduCommand.Le,
                        HasLe = apduCommand.HasLe
                    });
            }

            return this.commandParser.Build(
                new ApduCommand()
                {
                    Class = (byte)(apduCommand.Class | 0x04),
                    Instruction = apduCommand.Instruction,
                    P1 = apduCommand.P1,
                    P2 = apduCommand.P2,
                    Lc = (byte)(data.Length),
                    Data = data,
                    Le = apduCommand.Le,
                    HasLe = apduCommand.HasLe
                });
        }
    }
}