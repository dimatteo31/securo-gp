using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScpInfoProvider
    {
        ScpInfo Provide(byte[] cardRecognitionData);
    }
}