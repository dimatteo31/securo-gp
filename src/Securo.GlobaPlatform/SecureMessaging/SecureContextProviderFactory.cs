using Securo.GlobalPlatform.Cryptography;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System;
using System.Collections.Generic;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class SecureContextProviderFactory : ISecureContextProviderFactory
    {
        private readonly IGpMasterKeysProvider gpMasterKeysProvider;

        public SecureContextProviderFactory(IGpMasterKeysProvider gpMasterKeysProvider)
        {
            this.gpMasterKeysProvider = gpMasterKeysProvider;
        }

        public ISecureContextProvider Provide(ScpMode scpMode)
        {
            switch (scpMode)
            {
                case ScpMode.Scp02:
                    var scp02MacProviders = new List<IMacProvider>() { new SecureMessagingMacProvider(), new RetailMacProvider() };
                    var scp02CryptoProviders = new List<ICryptoProvider>() { new TrippleDesCryptoProvider(), new SingleDesProvider() };
                    var scp02SessionKeys = new Scp02SessionKeysProvider(gpMasterKeysProvider, scp02CryptoProviders);
                    return new Scp02SecureContextProvider(scp02MacProviders, scp02CryptoProviders, scp02SessionKeys);

                case ScpMode.Scp03:
                    var scp03MacProviders = new List<IMacProvider>() { new AesCmacProvider() };
                    var scp03cryptoProviders = new List<ICryptoProvider>() { new AesCbcProvider() };
                    var scp03sessionKeys = new Scp03SessionKeysProvider(gpMasterKeysProvider, scp03MacProviders);
                    return new Scp03SecureContextProvider(scp03MacProviders, scp03cryptoProviders, scp03sessionKeys);

                default:
                    throw new InvalidOperationException();
            }
        }
    }
}