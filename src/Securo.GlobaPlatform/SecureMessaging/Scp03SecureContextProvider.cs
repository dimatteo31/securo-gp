using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03SecureContextProvider : ISecureContextProvider
    {
        public SecureSessionDetails SecureSessionDetails { get; private set; }

        private readonly IEnumerable<IMacProvider> macProviders;
        private readonly IEnumerable<ICryptoProvider> cryptoProviders;
        private readonly IScp03SessionKeysProvider scp03SessionKeysProvider;
        private readonly IScp03Level1SecureMessagingWrapper scp03Level1SecureMessagingWrapper;
        private readonly IScp03Level3SecureMessagingWrapper scp03Level3SecureMessagingWrapper;
        private readonly IAuthenticationCryptogramProvider<Scp03HostAuthenticationCryptogramData> hostAuthenticationCryptogramProvider;
        private readonly IAuthenticationCryptogramProvider<Scp03CardAuthenticationCryptogramData> cardAuthenticationCryptogramProvider;

        public Scp03SecureContextProvider(
            IEnumerable<IMacProvider> macProviders,
            IEnumerable<ICryptoProvider> cryptoProviders,
            IScp03SessionKeysProvider scp03SessionKeysProvider)
        {
            this.macProviders = macProviders;
            this.cryptoProviders = cryptoProviders;
            this.scp03SessionKeysProvider = scp03SessionKeysProvider;
            
            this.hostAuthenticationCryptogramProvider = new Scp03HostAuthenticationCryptogramProvider(this.macProviders);
            this.cardAuthenticationCryptogramProvider = new Scp03CardAuthenticationCryptogramProvider(this.macProviders);
            this.scp03Level1SecureMessagingWrapper = new Scp03Level1SecureMessagingWrapper(this.macProviders);
            this.scp03Level3SecureMessagingWrapper = new Scp03Level3SecureMessagingWrapper(this.cryptoProviders);
        }

        public Task<string> CalculateHostCrypogram()
        {
            return Task.FromResult(
                this.hostAuthenticationCryptogramProvider.Calculate(SecureSessionDetails.SessionKeys.MacKey,
                new Scp03HostAuthenticationCryptogramData()
                {
                    CardChallenge = SecureSessionDetails.CardChallenge,
                    HostChallenge = SecureSessionDetails.HostChallenge
                }));
        }

        public void InitializeSecureContext(SecureSessionDetails secureSessionDetails)
        {
            this.SecureSessionDetails = secureSessionDetails;
            this.SecureSessionDetails.MacIv = "00000000000000000000000000000000";
            this.SecureSessionDetails.EncryptionIv = "00000000000000000000000000000000";
            this.SecureSessionDetails.IvCounter = 1;
            this.SecureSessionDetails.SessionKeys = this.scp03SessionKeysProvider.CalculateSessionKeys(
                this.SecureSessionDetails.HostChallenge,
                this.SecureSessionDetails.CardChallenge);

            var isVerfied = this.cardAuthenticationCryptogramProvider.Verify(
                this.SecureSessionDetails.SessionKeys.MacKey, new Scp03CardAuthenticationCryptogramData()
                {
                    CardChallenge = this.SecureSessionDetails.CardChallenge,
                    HostChallenge = this.SecureSessionDetails.HostChallenge
                }, this.SecureSessionDetails.CardCryptogram);

            if (!isVerfied)
            {
                throw new InvalidOperationException("Invalid card cryptogram");
            }
        }

        public Task<string> Unwrap(SecurityLevel securityLevel, string response)
        {
            switch (securityLevel)
            {
                case SecurityLevel.None:
                case SecurityLevel.Mac:
                case SecurityLevel.Mac_Enc:
                    return Task.FromResult(response);

                case SecurityLevel.Mac_RMac:
                    return Task.FromResult(
                        this.PerformSecMessagingLevel1(false, 
                            this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.RmacKey, response));

                case SecurityLevel.Mac_Enc_REnc_RMac:
                    this.PerformSecMessagingLevel1(false, 
                        this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.RmacKey, response);
                    return Task.FromResult(this.PerformSecMessagingLevel3(false, response));
            }

            throw new NotImplementedException();
        }

        public Task<string> Wrap(SecurityLevel securityLevel, string command)
        {
            switch (securityLevel)
            {
                case SecurityLevel.None:
                    return Task.FromResult(command);

                case SecurityLevel.Mac:
                case SecurityLevel.Mac_RMac:
                    return Task.FromResult(this.PerformSecMessagingLevel1(true, this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.MacKey, command));

                case SecurityLevel.Mac_Enc:
                case SecurityLevel.Mac_Enc_REnc_RMac:
                    var encryptedCommand = this.PerformSecMessagingLevel3(true, command);
                    return Task.FromResult(this.PerformSecMessagingLevel1(true, this.SecureSessionDetails.MacIv, this.SecureSessionDetails.SessionKeys.MacKey, encryptedCommand));

                default:
                    throw new NotImplementedException();
            }
        }

        private string PerformSecMessagingLevel1(bool isWrap, string iv, string key, string data)
        {
            this.scp03Level1SecureMessagingWrapper.SetUp(iv, key);
            string wrappedCommand;
            if (isWrap)
            {
                wrappedCommand = this.scp03Level1SecureMessagingWrapper.Wrap(data);
            }
            else
            {
                wrappedCommand = this.scp03Level1SecureMessagingWrapper.Unwrap(data);
            }

            this.SecureSessionDetails.MacIv = this.scp03Level1SecureMessagingWrapper.MacIv;
            return wrappedCommand;
        }

        private string PerformSecMessagingLevel3(bool isWrap, string command)
        {
            if (isWrap)
            {
                this.scp03Level3SecureMessagingWrapper.SetUp(
                                  this.SecureSessionDetails.EncryptionIv, this.SecureSessionDetails.SessionKeys.EncryptionKey, this.SecureSessionDetails.IvCounter++);
                var encryptedCommand = this.scp03Level3SecureMessagingWrapper.Wrap(command);
                return encryptedCommand;
            }
            else
            {
                this.scp03Level3SecureMessagingWrapper.SetUp(
                                  this.SecureSessionDetails.EncryptionIv, this.SecureSessionDetails.SessionKeys.EncryptionKey, this.SecureSessionDetails.IvCounter - 1);
                var unwrappedCommand = this.scp03Level3SecureMessagingWrapper.Unwrap(command);
                return unwrappedCommand;
            }
        }
    }
}
