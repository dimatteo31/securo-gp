using Securo.GlobalPlatform.Enums;
using Securo.GlobalPlatform.Interfaces;
using System.Collections.Generic;
using System.Linq;

namespace Securo.GlobalPlatform.SecureMessaging
{
    public class Scp03PseudoRandomCalculator : IScp03PseudoRandomCalculator
    {
        const int RandomLengthInBytes = 0x08;
        const string IterationCounter = "02";
        const string Label = "0000000000000000000000";
        private readonly IEnumerable<IMacProvider> macProviders;

        public Scp03PseudoRandomCalculator(IEnumerable<IMacProvider> macProviders)
        {
            this.macProviders = macProviders;
        }
    
        private string Build(string sequenceCounter, string aid)
        {
            return $"{Label}{IterationCounter}00004001{sequenceCounter}{aid}";
        }

        public string Generate(string key, string sequencecounter, string aid) 
        {
            var provider = this.macProviders.Single(x => x.Name == MacProvider.AesCmacProvider);
            var inputData = Build(sequencecounter, aid);
            return provider.Generate(string.Empty, key, inputData).Substring(0, RandomLengthInBytes * 2);
        }
    }
}