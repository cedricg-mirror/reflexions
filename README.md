# Reflexions

This repository is meant to share knownledge on malicious code targeting the Windows OS, whether they are state sponsored or cybercrime related.
The focus of my approach beeing dynamic analysis, I will be providing here logs resulting from runtime supervision of malware belonging to various APT/CyberCrime groups.

At this early stage, the logs provided have been designed to be human-readable and do not satisfy any known format that would make them suitable for a machine learning approach.
Log formating will be reworked in a future update of this project.

I do not plan to discuss attribution, samples analysed here are all coming from public reports from various sources that usually already provide their own insights on that topic.

# Repository

Analysed samples are stored according to the following pattern :  

[APT]/[APT_NAME]/[MALWARE_FAMILY]/[SHA256]/  
or  
[CyberCrime]/[MALWARE_FAMILY]/[SHA256]/  

Each directory contains : 
- text files logs resulting from my dynamic analysis 
- a README.md with information relative to the sample itself (source, reports, C2) as well as some of my observations / technical analysis 

# Understanding the log format

Analysed code behavior is logged, without surprise, in a chronological order.

## Typical log entry : 

```html
<1>[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
<2>[API] <GetProcAddress> in [KERNEL32.DLL] 
<3>[PAR] HMODULE hModule    : 0x00007FFE14200000 ("KERNEL32.DLL")
<4>[PAR] LPCSTR  lpProcName : 0x23fdfb ("LoadLibraryExW")
<5>[RET] 0x4640de in [go.exe]
```

1. **[ * ]** Describes the process id, thread id and process path associated with the logged API call.
2. **[API]** < API name > in [Module name]
3. and 4. **[PAR]** Parameters type, name : raw value and (interpreted value) when possible
5. **[RET]** Return address

## API call result :

```html
1. Call

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [API] <VirtualAllocEx> in [KERNEL32.DLL] 
Parameter : HANDLE hProcess     : 0xffffffff
Parameter : LPVOID lpAddress    : 0x0
Parameter : SIZE_T dwSize       : 0x3dbbf
Parameter : DWORD  flProtect    : 0x40 (PAGE_EXECUTE_READWRITE)
Return  @ : 0x2e4d113c9

2. Result from the above call

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [RES]  <VirtualAllocEx>  
Result    : LPVOID  0x000000FA94200000
```

At this stage, I only log API call results that I deem necessary for the analysis.  
In this above example, the result (0x000000FA94200000) from the VirtualAllocEx call is indicated by the **[RES]** flag.

## Structures :

```html
[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <bind> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x118
[PAR] struct sockaddr *name   : 0x000000C00009C46C
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 0 (Little endian : 0)
[FLD]          -> sin_addr     : 0.0.0.0
[PAR] int             namelen : 0x10
[RET] 0x4640de in [go.exe]
```

Whenever a pointer to a structure is passed as an argument to a function call, its relevant fields ([FLD]) will be dumped as demonstrated in the above example.  
The 2nd parameter to the **bind** call is a pointer to a **sockaddr** structure, each log entry starting with the '**[FLD]**' header indicates the name, raw value and interpreted value of relevant structure fields.

## Comments :

```html
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <SystemFunction032> in [CRYPTSP.DLL] 
Monitoring: [ i ] [ Undocumented RC4 implementation ]    <-- Comment field >
Parameter : PBINARY_STRING buffer : 0x000000FA9437E580
Field     :                -> Length    = 0x105
Field     :                -> MaxLength = 0x105
Field     :                -> Buffer    = 0x000000FA9234AA00 
Parameter : PBINARY_STRING key    : 0x000000FA9437E570
Field     :                -> Length    = 0x10
Field     :                -> MaxLength = 0x10
Field     :                -> Buffer    = 0x000000FA9234CBC0 ("S47EFEUO3D2O6641")
Return  @ : 0xfa942c4c35
```

I sometimes add information **[ i ]** to specific API call to spare some search engine time...

## Syntax Highlighting :  

I'm also sharing a very basic syntax highlighting profile for the logs here :  
https://github.com/cedricg-mirror/reflexions/tree/main/Logs_Syntax_Highlighting

![Alt text](Screenshots/syntax.jpg?raw=true "Basic Highlighting")

This profile is yet only compatible with the latest analysed samples due to various changes in the log format.
