using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Interfaces;
using System;
using System.Linq;

namespace Securo.GlobalPlatform.Model
{
    public class CardResponseParser : ICardResponseParser
    {
        const int StatusWordLengthBytes = 2;

        public CardResponse Parse(string cardResponse)
        {
            var statusWord = Hex.Decode(cardResponse.Substring(cardResponse.Length - StatusWordLengthBytes * 2, StatusWordLengthBytes * 2)).Reverse().ToArray();
            return new CardResponse()
            {
                FullResponse = cardResponse,
                Data = cardResponse.Substring(0, cardResponse.Length - StatusWordLengthBytes * 2),
                StatusWord = BitConverter.ToUInt16(statusWord)
            };
        }
    }
}
