using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class SecureSessionDetailsCreator : ISecureSessionDetailsCreator
    {
        const byte PseudoRandomCardNumberMask = 0x10;

        public SecureSessionDetails Create(string input)
        {
            var scpId = new InitializeResponseData().GetScpId(input);
            var scpMode = (ScpMode)Hex.Decode(scpId).First();

            switch (scpMode)
            {
                case ScpMode.Scp02:
                    var details = new Scp02InitializeResponseData().Parse(input);
                    return new SecureSessionDetails()
                    {
                        CardChallenge = details.CardChallenge,
                        SequenceCounter = details.SequenceCounter,
                        ScpInfo = new ScpInfo() { ScpIdentifier = (byte)ScpMode.Scp02 }
                    };

                case ScpMode.Scp03:
                    var scpOption = Hex.Decode(new Scp03InitializeResponseData().GetScpOption(input)).First();
                    if ((scpOption & PseudoRandomCardNumberMask) != 0x00)
                    {
                        var pseudoRandomDetails = new PseudoRandomScp03InitializeResponseData().Parse(input);
                        return new SecureSessionDetails()
                        {
                            CardChallenge = pseudoRandomDetails.CardChallenge,
                            SequenceCounter = pseudoRandomDetails.SequenceCounter,
                            ScpInfo = new ScpInfo() { ScpIdentifier = (byte)ScpMode.Scp03, ImplementationOptions = scpOption }
                        };
                    }

                    var trueRandomDetials = new TrueRandomScp03InitializeResponseData().Parse(input);
                    return new SecureSessionDetails()
                    {
                        CardChallenge = trueRandomDetials.CardChallenge,
                        ScpInfo = new ScpInfo() { ScpIdentifier = (byte)ScpMode.Scp03, ImplementationOptions = scpOption }
                    };

                default:
                    throw new InvalidOperationException();
            }
        }
    }
}