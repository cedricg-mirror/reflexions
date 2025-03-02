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





