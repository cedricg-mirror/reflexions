SHA256 : 4e8f24fb50a08c12636f3d50c94772f355d5229e58110cccb3b4835cb2371aec  
source : https://us-cert.cisa.gov/ncas/analysis-reports/ar21-105a  
sample source : https://github.com/MalwareSamples/Malware-Feed/  
VT : https://www.virustotal.com/gui/file/4e8f24fb50a08c12636f3d50c94772f355d5229e58110cccb3b4835cb2371aec    

Network / C2 : megatoolkit.com:443  

Analysed sample is a 64bit malware attributed by the CISA to APT29 and named SOLARFLARE by FireEye.  

Runtime analysis results are shared in two files :  

- logs.txt which contains a full execution trace of the malware until it awaits a C2 connection  
- conf.txt which is the setup that used for this sample, it contains notably the list of API calls which have been filtered out from the log  


*** Commentary *** 

Analyzed sample contains a few point of interest :

---- 

Wine detection :  

```html
[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <GetProcAddress> in [KERNEL32.DLL] 
[PAR] HMODULE hModule    : 0x00007FFE165B0000 ("ntdll.dll")
[PAR] LPCSTR  lpProcName : 0x23fe39 ("wine_get_version")
[RET] 0x4640de in [go.exe]
```  


---- 

As illustrated in the following code sequence, almost all API call have the same return address :  

```html
[ * ] [pid 0xb28][tid 0x828] c:\users\user\desktop\solar_flare\go.exe
[API] <SuspendThread> in [KERNEL32.DLL] 
[PAR] HANDLE hThread       : 0x80
[RET] 0x4640de 🡄🡄🡄

[ * ] [pid 0xb28][tid 0x654] c:\users\user\desktop\solar_flare\go.exe
[API] <VirtualQuery> in [KERNEL32.DLL] 
[PAR] LPCVOID                   lpAddress : 0x2771fec0
[PAR] PMEMORY_BASIC_INFORMATION lpBuffer  : 0x2771fec0
[PAR] SIZE_T                    dwLength  : 0x30
[RET] 0x4640de 🡄🡄🡄

[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <CloseHandle> in [KERNEL32.DLL] 
[PAR] HANDLE hObject    : 0x84
[RET] 0x4640de 🡄🡄🡄 
```

Below, the stub where all API call are directed :  

```asm
0033:004640b6 mov     rsi,rsp  
0033:004640b9 mov     rcx,qword ptr [rsi]  
0033:004640bc mov     rdx,qword ptr [rsi+8]  
0033:004640c0 mov     r8,qword ptr [rsi+10h]  
0033:004640c4 mov     r9,qword ptr [rsi+18h]  
0033:004640c8 movd    xmm0,rcx  
0033:004640cd movd    xmm1,rdx  
0033:004640d2 movd    xmm2,r8  
0033:004640d7 movd    xmm3,r9  
0033:004640dc call    rax  
0033:004640de add     rsp, 0x80  ; <----- 004640de : return address from most function call
0033:004640e5 pop     rcx  
0033:004640e6 mov     qword ptr [rcx+18h],rax  
0033:004640ea mov     rdi,qword ptr gs:[30h]  
0033:004640f3 mov     eax,dword ptr [rdi+68h]  
0033:004640f6 mov     qword ptr [rcx+28h],rax  
0033:004640fa ret  
```

This design hinders manual analysis but also create a single point of 'weakness' where it becomes possible to hook and supervise / modify most of the malware's activity.

---- 

The following code sequence is invalid :  

```html
[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <WSASocketW> in [ws2_32.dll] 
[PAR] int                address_family : 0x2 (AF_INET) (IPv4)
[PAR] int                type           : 0x1 (SOCK_STREAM) 🡄🡄🡄
[PAR] int                protocol       : 0x0 (NOT_SPECIFIED)
[PAR] LPWSAPROTOCOL_INFO lpProtocolInfo : 0x0
[PAR] GROUP              g              : 0x0
[PAR] DWORD              dwFlags        : 0x81
[RET] 0x4640de in [go.exe]

[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <setsockopt> in [ws2_32.dll] 
[PAR] SOCKET s       : 0x118
[PAR] int    level   : 0xffff (SOL_SOCKET)
[PAR] int    optname : 0x20 (SO_BROADCAST) 🡄🡄🡄
[PAR] char   *optval : 0x000000C0000BF3D8
[PAR] int    optlen  : 0x4
[RET] 0x4640de in [go.exe]
```

More specificaly, the option requested by setsockopt isn't compatible with the SOCK_STREAM type of the targeted socket and will always fail (error 10042).  


----

C2 connection :  

```html
[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <GetAddrInfoW> in [ws2_32.dll] 
[PAR] PCWSTR     pNodeName    : 0x000000C00000E2C0
[STR]            -> "megatoolkit.com"
[PAR] PCWSTR     pServiceName : 0x0 (null)
[PAR] ADDRINFOW  *pHints      : 0x000000C000037F18
[FLD] PADDRINFOW    pAddrInfo : 0x000000C000037F18
[FLD]               -> ai_flags     = 0x0 
[FLD]               -> ai_family    = 0x0 (AF_UNSPEC)
[FLD]               -> ai_socktype  = 0x1 (SOCK_STREAM)
[FLD]               -> ai_protocol  = 0x0 (NOT_SPECIFIED)
[FLD]               -> ai_addrlen   = 0x0
[FLD]               -> ai_canonname = 0x0 (null)
[FLD]               -> *ai_addr     = 0x0000000000000000
[FLD]               -> *ai_next     = 0x0000000000000000
[PAR] PADDRINFOW *ppResult    : 0x000000C000037E88
[RET] 0x4640de in [go.exe] 

[...]  
  
[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <WSAIoctl> in [ws2_32.dll] 
[PAR] SOCKET  s                 : 0x10c
[PAR] DWORD   dwIoControlCode   : 0xc8000006 (SIO_GET_EXTENSION_FUNCTION_POINTER)
[PAR] LPVOID  lpvInBuffer       : 0x8b2780 (WSAID_CONNECTEX)
[FLD]         -> InBuffer = {0x25a207b9,0xddf3,0x4660,0x8e,{0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
[RET] 0x4640de in [go.exe]

[ * ] [pid 0xb28][tid 0xb24] c:\users\user\desktop\solar_flare\go.exe
[API] <MSAFD_ConnectEx> in [mswsock.dll] 
[PAR] SOCKET          s                : 0x118
[PAR] struct sockaddr *name            : 0x000000C00009C44C
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 47873 (Little endian : 443)
[FLD]          -> sin_addr     : 169.254.143.42
[PAR] int             *namelen         : 0x10
[PAR] PVOID           lpSendBuffer     : 0x0
[PAR] DWORD           dwSendDataLength : 0x0
[PAR] LPDWORD         lpdwBytesSent    : 0x0
[PAR] LPOVERLAPPED    lpOverlapped     : 0x000000C0000CB270
[RET] 0x4640de in [go.exe] 
```

The sample attempts a HTTPS (443) connection to the IP associated with the domain "megatoolkit.com" (in this case 169.254.143.42).  
The connection is achieved through a call to the un-exported function MSAFD_ConnectEx from mswsock.dll.  
The address of the un-exported function is retrieved through a call to WSAIotl as demonstrated above.  

This trick may bypass EDR or other kind of userland supervision tool that would rely on hooks on more 'traditional' functions.  

