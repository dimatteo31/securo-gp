using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IApduTransmit
    {
        string ReaderName { get; }
        void Connect(string readerName);
        CardResponse Send(string apdu);
    }
}
