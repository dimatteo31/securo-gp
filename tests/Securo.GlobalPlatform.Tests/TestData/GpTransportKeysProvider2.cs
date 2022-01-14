using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Tests.TestData
{
    public class GpTransportKeysProvider2 : IGpMasterKeysProvider
    {
        public KeySet Provide()
        {
            return new KeySet()
            {
                EncryptionKey = "505152535455565758595A5B5C5D5E5F",
                MacKey = "606162636465666768696A6B6C6D6E6F",
                KeyEncryptionKey = "707172737475767778797A7B7C7D7E7F"
            };
        }
    }
}