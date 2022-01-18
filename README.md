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
select --aid=A000000003000000
open --kid 0 --kver 0 --scp=Mac
send --apdu=80F22002024F0000
```
