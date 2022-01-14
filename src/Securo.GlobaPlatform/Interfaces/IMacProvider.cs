using Securo.GlobalPlatform.Enums;

namespace Securo.GlobalPlatform.Interfaces
{
    public interface IMacProvider
    {
        MacProvider Name { get; }
        string Generate(string iv, string key, string input);
    }
}