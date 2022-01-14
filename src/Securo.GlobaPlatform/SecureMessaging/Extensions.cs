using Org.BouncyCastle.Utilities.Encoders;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public static class Extensions
    {
        public static byte[] ApplyPadding(this string input, int blockSize)
        {
            var inputPadded = Hex.Decode(input);
            if (inputPadded.Length % blockSize != 0)
            {
                var inputLength = inputPadded.Length;
                var blocks = inputPadded.Length / blockSize;
                var totalLength = (blocks + 1) * blockSize;
                inputPadded = inputPadded.Concat(new byte[totalLength - inputPadded.Length]).ToArray();
                inputPadded[inputLength] = 0x80;
            }

            return inputPadded;
        }

        public static IEnumerable<byte[]> Split(this byte[] value, int bufferLength)
        {
            var countOfArray = value.Length / bufferLength;
            if (value.Length % bufferLength > 0)
            {
                countOfArray++;
            }

            for (var i = 0; i < countOfArray; i++)
            {
                yield return value.Skip(i * bufferLength).Take(bufferLength).ToArray();
            }
        }
    }
}