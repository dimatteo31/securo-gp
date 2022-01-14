using System;
using System.Text.Json.Serialization;

namespace Securo.GlobalPlatform.Model
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ScpMode
    {
        Scp01 = 0x01,
        Scp02 = 0x02,
        Scp03 = 0x03
    }
}
