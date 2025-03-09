SHA256 : 875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24  
sample source : https://bazaar.abuse.ch/sample/875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24/  
VT : https://www.virustotal.com/gui/file/875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24  

Reports:  
https://dmpdump.github.io/posts/Lazarus-Backdoor-ITLure/  
https://ti.qianxin.com/blog/articles/Kimsuky-Weapon-Update:-Analysis-of-Attack-Activity-Targeting-Korean-Region/  


C2 :
http://www.addfriend.kr/board/userfiles/temp/index.html  

Analyzed sample is a 64bit PE PebbleDash sample attributed to LAZARUS  

---

In order to trigger the persistency-setup behavior from the sample a little reverse engineering was required :  

```html
[CNT] [13]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetCommandLineA> in [KERNEL32.DLL] 
[RET] 0x7ff7f099fd96 in [pebbledash.exe]

[CNT] [14]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetCommandLineW> in [KERNEL32.DLL] 
[RET] 0x7ff7f099fda3 in [pebbledash.exe]
```

Following the results from those call in statical analysis revealed the following :  

![Alt text](screen/start.jpg?raw=true "Command Line Parsing")

The sample was therefor run with the '--start' parameter, which triggered its installation :  

```html
[CNT] [64]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateProcessW> in [KERNEL32.DLL] 
[PAR] LPCWSTR               lpApplicationName   : 0x0 (null)
[PAR] LPCWSTR               lpCommandLine       : 0x00000025275BF1E0
[STR]                       -> "reg add hkcu\software\microsoft\windows\currentversion\run /d "\"C:\Users\user\Desktop\pebbledash\pebbledash.exe\"" /t R"
[STR]                          "EG_SZ /v "PAY" /f"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes  : 0x0
[PAR] BOOL                  bInheritHandles     : 0x0
[PAR] DWORD                 dwCreationFlags     : 0x0 
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCWSTR               lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOW        lpStartupInfo        : 0x00000025275BE970
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x1 (STARTF_USESHOWWINDOW)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x0
[FLD]                       -> hStdError   = 0x0
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x00000025275BE950
[RET] 0x7ff7f0997314 in [pebbledash.exe]
```

