SHA256 : 4e8f24fb50a08c12636f3d50c94772f355d5229e58110cccb3b4835cb2371aec  
source : https://us-cert.cisa.gov/ncas/analysis-reports/ar21-105a  
sample source : https://github.com/MalwareSamples/Malware-Feed/  
VT : https://www.virustotal.com/gui/file/4e8f24fb50a08c12636f3d50c94772f355d5229e58110cccb3b4835cb2371aec    

Network / C2 : megatoolkit.com:443  

Analyzed sample is a 64bit malware attributed by the CISA to APT29 and named SOLARFLARE by FireEye.  

Runtime analysis results are shared in two files :  

- full_log.txt which contains a full execution trace of the malware until it awaits a C2 connection  

- filtered_log.txt which contains the same execution trace but filtered from the following API calls in order to provide a better reading experience :  


```c
<ZwWaitForSingleObject> <CreateEventA> <SetEvent> <timeEndPeriod> <timeBeginPeriod> <WaitForSingleObject> <WaitForMultipleObjects>
<CloseHandle> <DuplicateHandle> <GetStdHandle> <SetHandleInformation> 
<VirtualAlloc> 
<GetThreadContext> <ResumeThread> <SuspendThread> <SwitchToThread>
<GetFileType> <GetConsoleMode>
<SetErrorMode> <RtlAddVectoredExceptionHandler> <RtlAddVectoredContinueHandler> 
<GetEnvironmentStringsW> <FreeEnvironmentStringsW>
```


*** Commentary *** 

Analyzed sample contains a few point of interest :

---- 

Wine detection :  

```c
Monitoring: [pid 0xa10][tid 0x464] c:\users\user\desktop\go.exe  
Monitoring: [API]  <GetProcAddress> in [KERNEL32.DLL]  
Parameter : HMODULE hModule    : 0x00007FFD19660000 (ntdll.dll)  
Parameter : LPCSTR  lpProcName : 0x23fe39 ("wine_get_version")  
Return  @ : 0x4640de
```  


---- 

As illustrated in the following code sequence, almost all API call have the same return address :  

```c
Monitoring: [pid 0xb7c][tid 0x7d0] c:\users\user\desktop\go.exe  
Monitoring: [API]  <SetEvent> in [KERNEL32.DLL]  
Parameter : HANDLE   hEvent : 0xc0  
Return  @ : 0x4640de  <---

Monitoring: [pid 0xb7c][tid 0x7d0] c:\users\user\desktop\go.exe  
Monitoring: [API]  <CloseHandle> in [KERNEL32.DLL]  
Parameter : HANDLE hObject    : 0x120  
Return  @ : 0x4640de  <---

Monitoring: [pid 0xb7c][tid 0x7c4] c:\users\user\desktop\go.exe  
Monitoring: [API]  <timeBeginPeriod> in [winmm.dll]  
Return  @ : 0x4640de  <---
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

This design hinder manual analysis but also create a single point of 'weakness' where it becomes possible to hook and supervise / modify most of the activity of the malware.

---- 

The following code sequence is invalid :  

```c
Monitoring: [pid 0x2a4][tid 0x56c] c:\users\user\desktop\go.exe  
Monitoring: [API]  <WSASocketW> in [ws2_32.dll]  
Parameter : int                address_family : 0x2 (AF_INET - IPv4)  
Parameter : int                type           : 0x1 (SOCK_STREAM)  
Parameter : int                protocol       : 0x0 (Not specified)  
Parameter : LPWSAPROTOCOL_INFO lpProtocolInfo : 0x0  
Parameter : GROUP              g              : 0x0  
Parameter : DWORD              dwFlags        : 0x81  
Return  @ : 0x4640de  

Monitoring: [pid 0x2a4][tid 0x56c] c:\users\user\desktop\go.exe  
Monitoring: [API]  <setsockopt> in [ws2_32.dll]  
Parameter : SOCKET s       : 0x118  
Parameter : int    level   : 0xffff (SOL_SOCKET)  
Parameter : int    optname : 0x20 (SO_BROADCAST)  
Parameter : char   *optval : 0x000000C0000CF3D8  
Parameter : int    optlen  : 0x4  
Return  @ : 0x4640de  
```

More specificaly, the option requested by setsockopt isn't compatible with the SOCK_STREAM type of the targeted socket and will always fail (error 10042).  


----

C2 connection :  

```c
Monitoring: [pid 0xa10][tid 0x464] c:\users\user\desktop\go.exe  
Monitoring: [API]  <GetAddrInfoW> in [ws2_32.dll]  
Parameter : PCWSTR     pNodeName    : 0x000000C00000E420  
            -> "megatoolkit.com"  
Parameter : PCWSTR     pServiceName : 0x0  
            -> (null)  
Parameter : ADDRINFOW  *pHints      : 0x000000C000085F18  
Parameter : PADDRINFOW *ppResult    : 0x000000C000085E88  
Return  @ : 0x4640de  

[...]  
  

Monitoring: [pid 0xa10][tid 0x464] c:\users\user\desktop\go.exe  
Monitoring: [API]  <WSAIoctl> in [ws2_32.dll]  
Parameter : SOCKET  s                 : 0x118  
Parameter : DWORD   dwIoControlCode   : 0xc8000006 (SIO_GET_EXTENSION_FUNCTION_POINTER)  
Parameter : LPVOID  lpvInBuffer       : 0x8b2780 (WSAID_CONNECTEX)  
                                       -> {0x25a207b9,0xddf3,0x4660,0x8e,{0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}  
Parameter : DWORD   cbInBuffer        : 0x10  
Parameter : LPVOID  lpvOutBuffer      : 0x8f3770  
Parameter : LPDWORD lpcbBytesReturned : 0x8  
Return  @ : 0x00007FFD18660464  

Monitoring: [pid 0xa10][tid 0x464] c:\users\user\desktop\go.exe  
Monitoring: [API]  <MSAFD_ConnectEx> in [mswsock.dll]  
Parameter : SOCKET          s                : 0x110  
Parameter : struct sockaddr *name            : 0x000000C00000E46C  
            -> sin_family   : 2 (IPv4)  
            -> sin_port     : 47873 (Little endian : 443)  
            -> sin_addr     : 42.42.42.42  
Parameter : int             *namelen         : 0x10  
Parameter : PVOID           lpSendBuffer     : 0x0  
Parameter : DWORD           dwSendDataLength : 0x0  
Parameter : LPDWORD         lpdwBytesSent    : 0x0  
Parameter : LPOVERLAPPED    lpOverlapped     : 0x000000C00003A370  
```

The sample attempt an HTTPS (443) connection with the IP associated with the domain "megatoolkit.com" (in this case 42.42.42.42).  
The connection is achieved through a call to the un-exported function MSAFD_ConnectEx from mswsock.dll.  
The address of the un-exported function is retrieved through a call to WSAIotl as demonstrated above.  

This trick may bypass EDR or other kind of userland supervision tool that would rely on hooks on more 'traditional' functions.  

