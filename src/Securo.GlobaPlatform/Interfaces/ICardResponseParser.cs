using Securo.GlobalPlatform.Model;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface ICardResponseParser
    {
        CardResponse Parse(string cardResponse);
    }
}
