SHA256 : 420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc  
source : https://bazaar.abuse.ch/sample/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc/  
VT : https://www.virustotal.com/gui/file/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc  

Network :  
http://checkip.dyndns.org/  
https://reallyfreegeoip.org/xml/  

C2:
api.telegram.org  
http://varders.kozow.com:8081  
http://aborters.duckdns.org:8081  
http://anotherarmy.dns.army:8081  

Report:  
https://www.infosecinstitute.com/resources/malware-analysis/redline-stealer-malware-full-analysis/  

Analysed redline stealer sample is a 32bit .NET DLL packaged within a 32bit executable.  

Runtime analysis results are shared in logs.txt which contains an execution trace until the sample tries to reach a C2.  
Targeted softwares for credentials harvesting are shared in target.txt.  

---  

*** Commentary ***

Runtime is divided in two main phases, the Win32 loader and the .NET payload.  
I haven't given too much thoughts regarding runtime analysis of .NET programs so far, but as it turns out it is still possible to collect many relevant information by indirectly looking at .NET behavior through the Win32 API.  

---  

In memory loading of the .NET DLL payload :   

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <CLRCreateInstance> in [mscoree.dll] 
[PAR] REFCLSID  clsid       : 0x41b230 ({9280188D-0E8E-4867-B30C-7FA83884E8DE})
[PAR] REFIID    riid         : 0x41b220 (ICLRMetaHost)
[PAR] LPVOID    *ppInterface : 0x269f6d0
[RET] 0x4021be

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICLRMetaHost::GetRuntime> in [mscoreei.dll] 
[PAR] LPCWSTR pwzVersion : 0x269f7c8 ("v4.0.30319")
[PAR] REFIID  riid       : 0x41b240 (ICLRRuntimeInfo)
[PAR] LPVOID  *ppRuntime : 0x269f6d4
[RET] 0x402215

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICLRRuntimeInfo::GetInterface> in [mscoreei.dll] 
[PAR] REFCLSID  clsid    : 0x41b210 ({74E03258-9E84-74E0-E013-960201000000})
[PAR] REFIID    riid     : 0x41b290 (ICorRuntimeHost)
[PAR] LPVOID     *ppUnk  : 0x269f69c
[RET] 0x40223b

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICorRuntimeHost::Start> in [clr.dll] 
[RET] 0x40224f

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICorRuntimeHost::GetDefaultDomain> in [clr.dll] 
[PAR] IUnknown **pAppDomain : 0x269f6a8
[RET] 0x4022b1

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <IUnknown::QueryInterface> in [clr.dll] 
[PAR] REFIID    riid         : 0x41b270 (_AppDomain)
[PAR] LPVOID    *ppv         : 0x269f6a4
[RET] 0x4022d9

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayCreate> in [OLEAUT32.dll] 
[PAR] VARTYPE         vt         : 0x11
[PAR] UINT            cDims      : 0x1
[PAR] SAFEARRAYBOUND  *rgsabound : 0x269f6d8
[FLD]                 rgsabound[0]
[FLD]                 -> cElements = 0x48000
[FLD]                 -> lLbound   = 0x0
[RET] 0x4022fc

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayAccessData> in [OLEAUT32.dll] 
[PAR] SAFEARRAY *psa       : 0x2967a58
[FLD]            -> cDims      = 0x1
[FLD]            -> fFeatures  = 0x80
[FLD]            -> cbElements = 0x1
[FLD]            -> cLocks     = 0x0
[FLD]            -> pvData     = 0x2991d90
[FLD]            -> cElements  = 0x48000
[FLD]            -> lLbound    = 0x0
[PAR] void      ** ppvData : 0x269f698
[RET] 0x40230e

DumpFile created : \DosDevices\C:\rtl_dump\MemDotNetD 

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayUnaccessData> in [OLEAUT32.dll] 
[PAR] SAFEARRAY *psa : 0x2967a58
[FLD]            -> cDims      = 0x1
[FLD]            -> fFeatures  = 0x80
[FLD]            -> cbElements = 0x1
[FLD]            -> cLocks     = 0x1
[FLD]            -> pvData     = 0x2991d90
[FLD]            -> cElements  = 0x48000
[FLD]            -> lLbound    = 0x0
[RET] 0x402324
```

This in-memory loading of managed code is well described here :  
https://0xpat.github.io/Malware_development_part_9/  
The loaded .NET DLL is dumped automatically by my sandbox and is now available here :  
https://www.virustotal.com/gui/file/af724ba9b889c902ae248039a93b86d53613dc966e648e4fe54ca2b10d0ea712/  
https://bazaar.abuse.ch/sample/af724ba9b889c902ae248039a93b86d53613dc966e648e4fe54ca2b10d0ea712/  

--- 

TODO following analysis  
