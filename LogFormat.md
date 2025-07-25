# Understanding the log format

Analysed code behavior is logged, without surprise, in a chronological order.

## Typical log entry : 

```html
<1>[CNT] [124]
<2>[PTP] [pid 0xb28][tid 0xb24] [c:\users\user\desktop\solar_flare\go.exe]
<3>[API] <GetProcAddress> in [KERNEL32.DLL] 
<4>[PAR] HMODULE hModule    : 0x00007FFE14200000 ("KERNEL32.DLL")
<4>[PAR] LPCSTR  lpProcName : 0x23fdfb ("LoadLibraryExW")
<5>[RET] 0x4640de in [go.exe]
```
1. **[CNT]** API call Counter  
2. **[PTP]** Describes the 'P'rocessID, 'T'hreadId and process 'P'ath associated with the logged API call.  
3. **[API]** < API_name > in [Module name]  
4. **[PAR]** Parameters type, name : raw value and (interpreted value) when possible/available  
5. **[RET]** Return address  

## API call result :

```html
1. Call

[PTP] [pid 0x728][tid 0x72c] [c:\users\user\desktop\apt10\apt10.exe]
[API] <VirtualAlloc> in [KERNEL32.DLL] 
[PAR] LPVOID lpAddress    : 0x0
[PAR] SIZE_T dwSize       : 0xe6e5
[PAR] DWORD  flProtect    : 0x40 (PAGE_EXECUTE_READWRITE)
[RET] 0x319086

2. Result from the above call

[ * ] [pid 0x728][tid 0x72c] [c:\users\user\desktop\apt10\apt10.exe]
[API] <VirtualAlloc>
[RES] LPVOID  0x1200000
```

At this stage, I only log API call results that I deem necessary for the analysis.  
In this above example, the result (0x1200000) from the VirtualAllocEx with PAGE_EXECUTE_READWRITE call is indicated by the **[RES]** header.

## Structures :

```html
[PTP] [pid 0xb28][tid 0xb24] [c:\users\user\desktop\solar_flare\go.exe]
[API] <bind> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x118
[PAR] struct sockaddr *name   : 0x000000C00009C46C
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 0 (Little endian : 0)
[FLD]          -> sin_addr     : 0.0.0.0
[PAR] int             namelen : 0x10
[RET] 0x4640de in [go.exe]
```

Whenever a pointer to a 'known' structure is passed as an argument to a function call, its relevant fields ([FLD]) will be dumped as demonstrated in the above example.  
The 2nd parameter to the **bind** call is a pointer to a **sockaddr** structure, each log entry starting with the '**[FLD]**' header indicates the name, raw value and interpreted value of relevant structure fields.

## Comments :

Comments are indicated by the [INF] header :

```html
[CNT] [324]
[PTP] [0xff8] [0x7dc] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x000000097A2FEA30
[FLD]                -> Length    = 0x10a
[FLD]                -> MaxLength = 0x10a
[FLD]                -> Buffer    = 0x0000000978307B70
[STR]                -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"mtdt":{"h_name":"home","wver":"x64/6.3","ip":"169.254.143.85","arch":"x64","bld":"96"
[STR]                   "00","p_name":"QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlAA==","uid":"user","pi"
[STR]                   "d":"4088","tid":"2012"}}\r\n"
[PAR] PBINARY_STRING key    : 0x000000097A2FEA20
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x000000097830CFF0
[STR]                -> "S47EFEUO3D2O6641"
[RET] [0x97a244c35]
```

I sometimes add information **[INF]** to specific API call to spare some search engine time...

## Syntax Highlighting :  

I'm also sharing a very basic syntax highlighting profile for the logs here :  
https://github.com/cedricg-mirror/reflexions/tree/main/Logs_Syntax_Highlighting

![Syntax highlighting](Screenshots/syntax.jpg?raw=true "Basic Highlighting")

This profile is yet only compatible with the latest analysed samples due to various changes in the log format.
