SHA256 : 0010ccb822538d1881c61be874af49382c44b6c9cb665081cf0f672cbed5b6a5  
source : https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/  
sample source : https://github.com/MalwareSamples/Malware-Feed/  
VT : https://www.virustotal.com/gui/file/0010ccb822538d1881c61be874af49382c44b6c9cb665081cf0f672cbed5b6a5  


C2 / Network :

api.dropboxapi.com:443  
content.dropboxapi.com:443  
hotspot.accesscam.org  
https://raw.githubusercontent.com/ksRD18pro/ksRD18/master/ntk.tmp



Analyzed sample is a 32bit DLL attributed to TURLA by ESET and named Crutch by the authors of the malware.

Results are shared in two files :  
- logs.txt which contains a full execution trace of the malware until it awaits a C2 connection  
- conf.txt which contains the configuration used to analyse this sample, notably the list of API call filtered from the logs  



