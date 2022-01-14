using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Org.BouncyCastle.Utilities.Encoders;
using PCSC;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.Application
{
    public class PcscReader : IApduTransmit
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private readonly IContextFactory contextFactory = ContextFactory.Instance;
        private ISCardContext sCardcontex;
        private ICardReader cardReader;
        public string ReaderName { get; private set; }

        public List<string> GetReaders()
        {
            using (var context = contextFactory.Establish(SCardScope.System))
            {
                return context.GetReaders().ToList();
            }
        }

        public void Connect(string readerName)
        {
            ReaderName = readerName;
            sCardcontex = contextFactory.Establish(SCardScope.System);
            cardReader = sCardcontex.ConnectReader(ReaderName, SCardShareMode.Shared, SCardProtocol.Any);
        }

        public string Transmit(string apdu)
        {
            var buff = new byte[258];
            var len = cardReader.Transmit(Hex.Decode(apdu), buff);
            return Hex.ToHexString(buff.Take(len).ToArray());
        }

        public CardResponse Send(string apdu)
        {
            log.Info($"TX:{apdu}");
            var buff = new byte[258];
            var len = cardReader.Transmit(Hex.Decode(apdu), buff);
            var resp = buff.Take(len).ToArray();
            log.Info($"RX:{Hex.ToHexString(resp.Take(resp.Length).ToArray())}");

            return new CardResponse()
            {
                FullResponse = Hex.ToHexString(resp.Take(resp.Length).ToArray()),
                Data = Hex.ToHexString(resp.Take(resp.Length - 2).ToArray()),
                StatusWord = BitConverter.ToUInt16(resp.Skip(resp.Length - 2).Reverse().ToArray())
            };
        }
    }
}
