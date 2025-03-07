SHA256 : 3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527  
sample source : https://bazaar.abuse.ch/sample/3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527/  
VT : https://www.virustotal.com/gui/file/3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527  

Report: https://cloud.google.com/blog/topics/threat-intelligence/turla-galaxy-opportunity?hl=en  

C2 :  
https://210.48.231.182/  

Analyzed sample is a 32bit .NET PE attributed to TURLA by Mandiant and named QUIETCANARY / Tunnus.  

Results are shared in two files :  

    logs.txt which contains a full execution trace of the malware until a successful C2 connection and order execution  
    logs_no_c2.txt which contains a full execution trace of the malware without successful C2 connection  


---  

**Commentary**  

As a reminder, the sandbox that I'm developping doesn't provide any proper interface to monitor managed code (yet).  
Supervision of managed code is done indirectly by monitoring activity from native DLL loaded by the monitored process.  
As a consequence, logs provided are 'noisy', the same kind of noise you would get by monitoring syscall instead of Win32 API for instance.  
 
---  

This sample is so minimalistic that dynamic analysis alone is basically only usefull to provide the C2 :  

```html
[...]

[CNT] [49]
[PTP] [0xba8] [0xbac] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <WSAConnect> in [WS2_32.dll] 
[PAR] SOCKET   s     : 0x3d8
[PAR] sockaddr *name : 0x0000009B393446A8
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 47873 (Little endian : 443)
[FLD]          -> sin_addr     : 210.48.231.182
[RET] 0x7ff817b03542 in [System.ni.dll]

[ * ] [pid 0xba8][tid 0xbac] c:\users\user\desktop\quiet_canary\canary.exe
[EVT] [Max Sleep]
[MSG] Delay Execution reduced from 300000 ms to 15000 ms 
```

Results of dynamic analysis without a working C2 is provided in the attached 'logs_no_c2.txt' file.  

---  

Going further, I decided to use some statical analysis and develop a bare minimum C2 to trigger some additional behavior from the sample :  

![Alt text](screenshots/init.jpg?raw=true "first beaconing")

Statical analysis is very straightforward as this sample isn't obfuscated in any way.

Now, the first beaconing to the C2 is a HTTP GET request with a hardcoded useragent.  
The initial RC4 Key, that the C2 will have to use in reply to that first beaconing, is also visible in that screenshot.   

```cs
 using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            empty = Encoding.UTF8.GetString(RC4Encryption.EncryptDecrypt(Convert.FromBase64String(streamReader.ReadToEnd()), this.initialKey));
```




QUIETCANARY is expecting the following answer from the C2 :  

![Alt text](screenshots/new_rc4_key.jpg?raw=true "New Rc4 Key")

In other words, the keyword "use" followed by a 10 letters string that is going to be used as a new RC4 key to encrypt communications.  

