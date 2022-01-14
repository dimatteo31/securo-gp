using Org.BouncyCastle.Utilities.Encoders;
using System;

namespace Securo.GlobalPlatform.Model
{
    [Serializable]
    public class ApduCommand
    {
        public byte Class { get; set; }
        public byte Instruction { get; set; }
        public byte P1 { get; set; }
        public byte P2 { get; set; }
        public byte Lc { get; set; }
        public byte[] Data { get; set; }
        public byte Le { get; set; }
        public bool HasLe { get; set; }
        public int Sw { get; set; }

    }
}
