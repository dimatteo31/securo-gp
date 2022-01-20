using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Tests.TestData
{
    public class GpTransportKeysProviderAes192 : IGpMasterKeysProvider
    {
        public KeySet Provide()
        {
            return new KeySet()
            {
                EncryptionKey = "404142434445464748494a4b4c4d4e4f4041424344454647",
                MacKey = "404142434445464748494a4b4c4d4e4f4041424344454647",
                KeyEncryptionKey = "404142434445464748494a4b4c4d4e4f4041424344454647"
            };
        }
    }
}