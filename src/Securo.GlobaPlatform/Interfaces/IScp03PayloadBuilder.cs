namespace Securo.GlobalPlatform.Interfaces
{
    public interface IScp03PayloadBuilder
    {
        string UpdatedCommand { get; }
        string BuildPayload(string iv, string command);
    }
}