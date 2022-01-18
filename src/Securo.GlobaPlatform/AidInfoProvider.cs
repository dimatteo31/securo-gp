using BerTlv;
using Securo.GlobalPlatform.Interfaces;
using System.Linq;

namespace Securo.GlobalPlatform
{
    public class AidInfoProvider : IAidInfoProvider
    {
        public string Provide(string fciTemplate)
        {
            return Tlv.ParseTlv(fciTemplate).First().Children.First().HexValue;
        }
    }
}
