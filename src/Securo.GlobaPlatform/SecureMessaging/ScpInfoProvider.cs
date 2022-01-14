using BerTlv;
using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class ScpInfoProvider : IScpInfoProvider
    {
        const int OffsetScpId = 0;
        const int OffsetImplementationOptions = 1;

        public ScpInfo Provide(byte[] data)
        {
            var oidForScp = Tlv.ParseTlv(data).First().Children.First().Children.Single(x => x.Tag == (int)CardRecognitonDataApplicationTag.Tag4).Value;
            var scpInfoBytes = oidForScp.Skip(oidForScp.Count() - 2).ToArray();
            return new ScpInfo()
            {
                ScpIdentifier = scpInfoBytes[OffsetScpId],
                ImplementationOptions = scpInfoBytes[OffsetImplementationOptions]
            };
        }
    }
}