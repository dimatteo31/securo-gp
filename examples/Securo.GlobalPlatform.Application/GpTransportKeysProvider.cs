using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Application
{
    public class GpTransportKeysProvider : IGpMasterKeysProvider
    {
        public KeySet Provide()
        {
            return new KeySet()
            {
                EncryptionKey = "404142434445464748494a4b4c4d4e4f",
                KeyEncryptionKey = "404142434445464748494a4b4c4d4e4f",
                MacKey = "404142434445464748494a4b4c4d4e4f"
            };
        }
    }
}
