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

/*
2022 - 01 - 20 21:16:50,562 INFO - Command connect => [PcscReader = Broadcom Corp Contacted SmartCard 0]
2022 - 01 - 20 21:16:50,784 INFO - Command set_keys => [EncKey = 404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f | MacKey = 404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f]
2022 - 01 - 20 21:16:50,786 INFO - Command select => [Aid =]
2022 - 01 - 20 21:16:50,810 INFO - TX - Wrap-> 00A4040000
2022 - 01 - 20 21:16:50,845 INFO - RX - Wrap < -6F108408A000000151000000A5049F6501FF9000
2022 - 01 - 20 21:16:50,864 INFO - TX - Wrap-> 00A4040008A000000151000000
2022 - 01 - 20 21:16:50,878 INFO - RX - Wrap < -9000
2022 - 01 - 20 21:16:50,878 INFO - TX - Wrap-> 80CA006600
2022 - 01 - 20 21:16:50,897 INFO - RX - Wrap < -663F733D06072A864886FC6B01600C060A2A864886FC6B02020201630906072A864886FC6B03640B06092A864886FC6B040370660C060A2B060104012A026E01029000
2022 - 01 - 20 21:16:50,900 INFO - Command open => [SecuirtyLevel = Mac_Enc_REnc_RMac | KeyId = 0 | KeySetVersion = 0]
2022 - 01 - 20 21:16:50,902 INFO - TX - Wrap-> 8050000008AECA2F67DBAAE34000
2022 - 01 - 20 21:16:51,023 INFO - RX - Wrap < -000003460206160900440103700A1D17F6856F7EFCD63933F9A779FB37 00000E 9000
2022 - 01 - 20 21:17:23,935 INFO - TX - Wrap-> 84823300105984A45B573C5A748BDDC72592BB41D6
2022 - 01 - 20 21:17:24,017 INFO - RX - Wrap < -9000
2022 - 01 - 20 21:17:24,018 INFO - Command send:[ApduCommand= 80F22002024F0000]
2022 - 01 - 20 21:17:24,019 INFO - TX - Plain-> 80F22002024F0000
2022 - 01 - 20 21:17:24,031 INFO - TX - Wrap-> 84F2200218F55B6CE501DC96B36D6CE334B973D712C7B48C9D1447105100
2022 - 01 - 20 21:17:24,146 INFO - RX - Wrap < -E81D87C1D08615F9F2AFCA1914289B2BDB11AE59E99C17769000
2022 - 01 - 20 21:17:24,163 INFO - RX - Plain->E30D4F07A00000015153509F7001019000
2022 - 01 - 20 21:17:24,164 INFO - Command send:[ApduCommand= 80F22002024F0000]
2022 - 01 - 20 21:17:24,164 INFO - TX - Plain-> 80F22002024F0000
2022 - 01 - 20 21:17:24,164 INFO - TX - Wrap-> 84F220021837A7D0CC05361B016F41664C9E99BA0AA581EB044BE9705100
2022 - 01 - 20 21:17:24,279 INFO - RX - Wrap < -6349C6A396D14331A7B1F09DBFD2F64C93CAA9D891E109F49000
2022 - 01 - 20 21:17:24,279 INFO - RX - Plain->E30D4F07A00000015153509F7001019000
*/