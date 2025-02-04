# Reflexions

This repository is meant to share knownledge on malicious code targeting the Windows OS, whether they are state sponsored or cybercrime related.
The focus of my approach beeing dynamic analysis, I will be providing here logs resulting from runtime supervision of malware belonging to various APT/CyberCrime groups.

At this early stage, the logs provided have been designed to be human-readable and do not satisfy any known format that would make them suitable for a machine learning approach.
Log formating will be reworked in a future update of this project.

I do not plan to discuss attribution, samples analyzed here are all coming from public reports from various sources that usually already provide their own insights on that topic.


# Understanding the log format

Analyzed code behavior is logged, without surprise, in a chronological order.

* **Typical log entry** : 

```html
1. Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
2. Monitoring: [API] <GetProcAddress> in [KERNEL32.DLL] 
3. Parameter : HMODULE hModule    : 0x00007FF9B24D0000 ("KERNELBASE.dll")
4. Parameter : LPCSTR  lpProcName : 0x00000001801027B8 ("InitializeCriticalSectionEx")
5. Return  @ : 0x1800b281e
```

1. Describes the process id, thread id and process path associated with the logged API call.
2. **[API]** < API name > in [Module name]
3. and 4. Parameters type, name : raw value and (interpreted value) when possible
5. Return address

* **API call result :**

```html
Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [API] <VirtualAllocEx> in [KERNEL32.DLL] 
Parameter : HANDLE hProcess     : 0xffffffff
Parameter : LPVOID lpAddress    : 0x0
Parameter : SIZE_T dwSize       : 0x3dbbf
Parameter : DWORD  flProtect    : 0x40 (PAGE_EXECUTE_READWRITE)
Return  @ : 0x2e4d113c9

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [RES]  <VirtualAllocEx>  
Result    : LPVOID  0x000000FA94200000
```

At this stage, I only log API call results that I deem necessary for the analysis.  
In this above example, the result (0x000000FA94200000) from the VirtualAllocEx call is indicated by the **[RES]** flag.

* **Structures :**

```html
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <NtSetContextThread> in [ntdll.dll] 
Monitoring: [ ! ] [ Attempt to bypass hooked API detected ! ]
Parameter : HANDLE   ThreadHandle : 0xfffffffe
Parameter : PCONTEXT Context      : 0x000000FA9437E100
Field     :          -> ContextFlags = 0x100010 (CONTEXT_DEBUG_REGISTERS)
Field     :          -> Dr0          = 0x00007FF9B5342630 (ntdll.dll!NtTraceControl)
Field     :          -> Dr7          = 0x1
Return  @ : 0xfa942d816e
```

Whenever a pointer to a structure is passed as an argument to a function call, its relevant fields will be dumped as demonstrated in the above example.  
The 2nd parameter to the NtSetContextThread syscall is a pointer to a CONTEXT structure, each log entry starting with the '**Field :**' header indicates the name, raw value and interpreted value of relevant structure fields.

* **Comments**

```html
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <SystemFunction032> in [CRYPTSP.DLL] 
Monitoring: [ i ] [ Undocumented RC4 implementation ]
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

I sometime add information **[ i ]** to specific API call to spare some search engine time...

