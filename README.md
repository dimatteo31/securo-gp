# securo-gp
This project implements Global Platform (https://globalplatform.org) Secure Channel Protcol (SCP) in version SCP02 and SCP03.

## Securo.GlobaPlatform
All security levels are supported for SCP03:
* C-DECRYPTION, R-ENCRYPTION, CMAC and R-MAC
* C-DECRYPTION, C-MAC and R-MAC
* C-MAC and R-MAC
* C-DECRYPTION and C-MAC
* C-MAC
* No secure messaging

## Securo.GlobaPlatform.Application
Simple CLI script application for handling GP smart card. To run the application following args shall be passed:
``` 
securo-gp-app --script script.txt
``` 
Input script supports command set described in table below

| Command  	| Description                                                     	|
|----------	|-----------------------------------------------------------------	|
| connect  	| Performs connection to PCSC reader (card must be inserted)      	|
| send     	| Sends APDU with security level requested during sc_open command 	|
| set_keys 	| Sets GP keys [enc\|mac\|dek]                                    	|
| select   	| Selects GP applet                                               	|
| open     	| Opens secure channel with GP card                               	|

Sample script can have the following command set. It opens secure channel with GP Card Manager with transport keys. The requested security level is Mac (0x01).
``` 
connect --reader="Broadcom Corp Contacted SmartCard 0"
set_keys --key_enc=404142434445464748494a4b4c4d4e4f --key_mac=404142434445464748494a4b4c4d4e4f --key_dek=404142434445464748494a4b4c4d4e4f
select
open --kid 0 --kver 0 --scp=Mac
send --apdu=80F22002024F0000
```
The script shall have the following results:
```
INFO - Command connect => [PcscReader=Broadcom Corp Contacted SmartCard 0]
INFO - Command set_keys => [EncKey=404142434445464748494a4b4c4d4e4f|MacKey=404142434445464748494a4b4c4d4e4f]
INFO - Command select => [Aid=]
INFO - TX-Wrap  -> 00A4040000
INFO - RX-Wrap  <- 6F108408A000000151000000A5049F6501FF9000
INFO - TX-Wrap  -> 00A4040008A000000151000000
INFO - RX-Wrap  <- 9000
INFO - TX-Wrap  -> 80CA006600
INFO - RX-Wrap  <- 663F733D06072A864886FC6B01600C060A2A864886FC6B02020201630906072A864886FC6B03640B06092A864886FC6B040360660C060A2B060104012A026E01029000
INFO - Command open => [SecuirtyLevel=Mac|KeyId=0|KeySetVersion=0]
INFO - TX-Wrap  -> 8050000008C68A990B2BFCB8C600
INFO - RX-Wrap  <- 00000346020614090044010360CF7B1ACE86B043D6C3F8E7CD08769A709000
INFO - TX-Wrap  -> 8482010010ADAEE70AB303E5CACFB26C961BAA1E22
INFO - RX-Wrap  <- 9000
INFO - Command send: [ApduCommand=80F22002024F0000]
INFO - TX-Plain -> 80F22002024F0000
INFO - TX-Wrap  -> 84F220020A4F00B46CED16DE49800600
INFO - RX-Wrap  <- E30D4F07A00000015153509F7001019000
INFO - RX-Plain -> E30D4F07A00000015153509F7001019000
```
