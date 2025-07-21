# Configuration File  

Beeing a sandbox as much as a debugging assisting tool, Reflexions can be configured to collect or ignore specific events during analysis as well as alter the supervised code's behavior.  

The configuration is therefore meant to be malware specific, in most cases the analyst will run his sample several times, analyze the logs and fine tune the configuration between each run.  

The configuration can then be reused for any analysis of a sample of the same malware family or be shared along an analyzed sample to enable other analyst to replicate the same result.  

As it stands right now, Reflexions GUI only offers some of the features offered by the configuration file  

<details>
  <summary>
	Empty configuration file sample (click to expand)
  </summary>
	
```xml
<rfx_config>
	<TARGET>
		<TARGET_PROCESS path=""/> 
		
		<TARGET_DLL>
			<DLL path=""/>
			<DLL path=""/>
			<SUPERVISE_TARGET_DLL_ANY_PROCESS isactive="0"/>
			<AUTO_SUPERVISE_DROPPED_DLL isactive="0"/>
		</TARGET_DLL>
		
		<DLL_MONITORING_LEVEL level="1"/>
		<SUPERVISE_DLL_DEPENDENCY isactive="0"/>
	</TARGET>
	
	<BLACKLIST>
		<IGNORED_DLLS>
			<DLL name=""/>
			<DLL name=""/>
		</IGNORED_DLLS>
		
		<IGNORED_API>
		</IGNORED_API>
		
		<IGNORED_PROCESSES>
			<PROCESS path=""/>
			<PROCESS path=""/>
		</IGNORED_PROCESSES>
	</BLACKLIST>
	
	<SHELLCODE>
		<SUPERVISE_FROM_SHELLCODE_DETECTION isactive="0"/>
		<BREAK_UPON_SHELLCODE_DETECTION isactive="0"/>
		<IGNORE_DECOY_PROCESS isactive="0"/>
	</SHELLCODE>
	
	<BREAKPOINTS>
		<KERNEL_BP isactive="0">
			<BP function="" min_counter="1" max_counter="0" is_oneshot="0" msg="" isactive="0"/>
			<BP function="" min_counter="1" max_counter="0" is_oneshot="0" msg="" isactive="0"/>
		</KERNEL_BP>
		<IGNORE_USER_CC_BREAKPOINTS isactive="0">
			<IGNORE_FROM_EXE isactive="0"/>
			<IGNORE_FROM_DLL isactive="0"/>
			<IGNORE_FROM_MEMORY isactive="0"/>
			<IGNORE_FOR_ALL_PROCESSES isactive="0"/>
		</IGNORE_USER_CC_BREAKPOINTS>
	</BREAKPOINTS>
	
	<REMOTE_EXECUTION>
		<SUPERVISE_REMOTE_THREADS isactive="0"/>
		<MONITOR_CHILD_PROCESS isactive="0"/>
		<CLONE_OPEN_PROCESS isactive="0"/>
	</REMOTE_EXECUTION>
	
	<NETWORK>
		<SPOOF_ALL_DOMAINS spoofed_ip="" isactive="0"/>
		<DISABLE_SSL isactive="0"/>
		<SPOOF_DOMAINS>
			<DOMAIN name="" spoofed_ip=""/>
			<DOMAIN name="" spoofed_ip="" />
		</SPOOF_DOMAINS>
		<SPOOF_IP>
			<IP legit_ip="" spoofed_ip=""/>
			<IP legit_ip="" spoofed_ip=""/>
		</SPOOF_IP>
	</NETWORK>
	
	<OUTPUT>
		<DUMP_CREATED_FILES dir_path="" isactive="0"/>
		<LOG_EVENTS_TO_FILE dir_path="" isactive="0"/>
		<OUTPUT_TO_DEBUGGER isactive="0"/>
		<FLOOD_FILTER max_count="0"/>
	</OUTPUT>
	
	<MAX_SLEEP delay_in_ms="0"/>
	<PATCH_PEB_LDR isactive="0"/>
	<HIDE_VM isactive="0"/>
	
	<STOP_CONDITION>
		<API_COUNT max_count="0"/>
		<LOG_SIZE limit_MB="0"/>
		<ELAPSED_TIME limit_s="0"/>
	</STOP_CONDITION>
	
	<ENABLE_HOOK_HEURISTIC isactive="0"/>
</rfx_config>
```
</details>

1. [TARGET](#target)
2. [BLACKLIST](#blacklist)
3. [SHELLCODE](#shellcode)
4. [BREAKPOINTS](#breakpoints)
5. [REMOTE EXECUTION](#remote_execution)

## Target <a name="target"></a>

This section defines the target of the analysis.

GUI:  
![Target](Screenshots/target.jpg?raw=true "Target")  

Conf:  
```xml
<TARGET>
	<TARGET_PROCESS path=""/> 
		
	<TARGET_DLL>
		<DLL path=""/>
		<DLL path=""/>
		<SUPERVISE_TARGET_DLL_ANY_PROCESS isactive="0"/>
		<AUTO_SUPERVISE_DROPPED_DLL isactive="0"/>
	</TARGET_DLL>
		
	<DLL_MONITORING_LEVEL level="1"/>
	<SUPERVISE_DLL_DEPENDENCY isactive="0"/>
</TARGET>
```

* **Process Path :**

If the target is an executable, defines either the name, partial or full path to that executable.  

GUI:  
![Process Path](Screenshots/process_path.jpg?raw=true "Process Path")  

Conf:  
```xml
<TARGET_PROCESS path=""/>
```

Most of the time using the executable name is sufficient :  
```xml
<TARGET_PROCESS path="malware.exe"/>
```
however if the sample requires to be lauched under a specific name mimicking a legitimate binary like "svchost.exe" then a partial :  
```xml
<TARGET_PROCESS path="malware\svchost.exe"/>
```
or full path :  
```xml
<TARGET_PROCESS path="C:\ProgramData\svchost.exe"/>
```
is required to avoid analysing a legitimate binary that could be started during the analysis (in this case "C:\Windows\System32\svchost.exe").  

* **DLL monitoring level:**

This settings defines which DLL should trigger a log whenever the supervised code calls one of it's function.  
This setting applies whether a DLL is statically or dynamically linked by the supervised code.  

GUI:  
![Monitoring level](Screenshots/monitoring_level.jpg?raw=true "Monitoring level")  

Conf:  
```xml
<DLL_MONITORING_LEVEL level="1"/>
<SUPERVISE_DLL_DEPENDENCY isactive="0"/>
```

Kernel32 / <DLL_MONITORING_LEVEL level="0"/> :
Only calls to Kernel32.dll will trigger a log  

System32 / <DLL_MONITORING_LEVEL level="1"/> :
Any call to any DLL located in System32 will trigger a log, this is the default setting   

All / <DLL_MONITORING_LEVEL level="2"/> :
Any call to any DLL statically or Dynamically linked by the supervised code will trigger a log  

Dependencies :  

By default, Reflexions will only monitor DLL which have been either statically linked or *explicitly* loaded at runtime by the supervised code.  
This implies that if DLL1 is loaded at runtime and DLL1 imports DLL2, Reflexions, as an optimization,  will ignore any activity towards DLL2.  

It is possible to override this default behavior by also monotoring DLL loaded as a dependency of a dynamically loaded DLL :  
![dependencies](Screenshots/dependencies.jpg?raw=true "dependencies")  


* **Dll Path :**  

If the target is a DLL, defines either the name, partial or full path to that DLL.  
This field can be used independently from the process path.  

GUI:  
![Dll Path](Screenshots/dll_path.jpg?raw=true "DLL Path")  

While the GUI only allows for a single target DLL to be specified , the configuration file allows any number of targeted DLL :  

Conf:  
```xml
<DLL path="malware1.dll"/>
<DLL path="malware\mfc42.dll"/>
...
```

If the analyst isn't interested by monotoring the activity of the process loading the DLL (ie rundll32.exe) then process path can be left empty.  
In that case, if "System Wide Monitoring" is selected, the DLL will be supervised in any process it'll be loaded into :  

GUI:  
![System Wide Monitoring](Screenshots/dll_any_process.jpg?raw=true "System Wide Monitoring")  

Conf:  

```xml
<SUPERVISE_TARGET_DLL_ANY_PROCESS isactive="1"/>
```

If the DLL name cannot be known before starting the analysis (DLL dropped with a random name for instance) it is possible to attempt an automatic detection :  

GUI:  
![Auto supervise dropped DLL](Screenshots/auto_dll.jpg?raw=true "Auto supervise dropped DLL") 

```xml
<AUTO_SUPERVISE_DROPPED_DLL isactive="1"/>
```

This features enables Reflexions to attempt to automatically detect and supervise any DLL that would be dropped and loaded during analysis.  


## Blacklist  <a name="blacklist"></a>

This section is for now only available through the configuration file :  

```xml
<BLACKLIST>
	<IGNORED_DLLS>
		<DLL name=""/>
		<DLL name=""/>
	</IGNORED_DLLS>
	
	<IGNORED_API>
	</IGNORED_API>
	
	<IGNORED_PROCESSES>
		<PROCESS path=""/>
		<PROCESS path=""/>
	</IGNORED_PROCESSES>
</BLACKLIST>
```

As the name suggest, it allows the analyst to prevent Reflexions from supervising any specified DLL, API function or process during the analysis.  
For instance, if the target of the analysis is a process displaying a GUI, one could prevent any call to GDI32.DLL to be recorded :  

```xml
<IGNORED_DLLS>
	<DLL name="GDI32.DLL"/>
</IGNORED_DLLS>
```

Another option would of course be filtering the logs *after* the analysis, however it is important to understand that any supervised call induce an important performance overhead.  
This is especially true while using Reflexions in connection with a kernel debugger where every uncesseray supervised call will slow down the execution flow by a significant amount.  

For instance, let's imagine a code that would call 'memcmp' a million time in a row.  
If this call is supervised while connected to a debugger, then 'memcmp' would have to be dispayed (DbgPrint) a million time before the code could reach a part of interrest to the analyst.  
One way to solve that issue would be to blacklist calls to memcmp altogether :  

```xml
<IGNORED_API>
	<memcmp>
</IGNORED_API>
```

Note : this part of the configuration file is *NOT* xml compliant for now.  
Another way would be to use the anti-flood setting (see further down).  

If Reflexions is configured to automatically supervise any child process from the initial target (see further down), then it may be of interest to prevent Reflexions to record specific processes activity.  
For instance, if malware.exe is spawing a cmd.exe process a some point, it is unlikely that the analyst would be interested in recording all the activity from cmd.exe (since the command line parameter would be self-explaining) :  

```xml
<IGNORED_PROCESSES>
	<PROCESS path="C:\Windows\system32\cmd.exe"/>
</IGNORED_PROCESSES>
```

In other words, blacklisting DLL, API or processes isn't just about generating 'cleaner' logs, but also about limiting Reflexions overhead during analysis and also about limiting any potential side effect from the deep tempering induced by Reflexions of any supervised process.  

## Shellcode <a name="shellcode"></a>

Those settings aims at detecting code that would be executed either outside a legitimate module (meaning from allocated memory) or through Return Oriented Programming.  
I designed those features at a time where exploit documents were prevalent, it may not be as useful nowadays  

GUI:  
![Shellcode](Screenshots/shellcode.jpg?raw=true "shellcode")  

Conf:  
```xml
<SHELLCODE>
	<SUPERVISE_FROM_SHELLCODE_DETECTION isactive="0"/>
	<BREAK_UPON_SHELLCODE_DETECTION isactive="0"/>
	<IGNORE_DECOY_PROCESS isactive="0"/>
</SHELLCODE>
```

* Log upon shellcode detection :

Reflexions will start logging upon the first API function called from outside a legitimate module or through a ROP Gadget.  

* Break on first API :

If Reflexions is connected to a kernel debugger, a breakpoint will automatically be triggered on the first function called by the 'shellcode'  

* Ignore Decoy :
  
This setting is very specific to exploit documents, if set Reflexions will only supervise the first instance of the target process (winword.exe for instance).
A second instance (like the one initiated to dispay a decoy decoment) would not trigger any log

## Breakpoints <a name="breakpoints"></a>  

This section allows the analyst to set undectable kernel breakpoints and/or prevent user software breakpoint to be forwarded to the debugger.  

GUI:  
![Breakpoints](Screenshots/breakpoints.jpg?raw=true "breakpoints")  

Conf:  
```xml
<BREAKPOINTS>
	<KERNEL_BP isactive="0">
		<BP function="" min_counter="1" max_counter="0" is_oneshot="0" msg="" isactive="0"/>
		<BP function="" min_counter="1" max_counter="0" is_oneshot="0" msg="" isactive="0"/>
	</KERNEL_BP>
	<IGNORE_USER_CC_BREAKPOINTS isactive="0">
		<IGNORE_FROM_EXE isactive="0"/>
		<IGNORE_FROM_DLL isactive="0"/>
		<IGNORE_FROM_MEMORY isactive="0"/>
		<IGNORE_FOR_ALL_PROCESSES isactive="0"/>
	</IGNORE_USER_CC_BREAKPOINTS>
</BREAKPOINTS>
```

* Kernel BreakPoint :

Reflexions allows for a kernel breakpoint to be triggered whenever a specified function is called by the supervised code.  
The GUI only allows, for now, for a single function to trigger a breakpoint :

![Kernel Breakpoint](Screenshots/kernelbp.jpg?raw=true "kernel breakpoint")  

By default, a breakpoint will be triggered each time the specified function is called by the supervised code.  
To allow for a breakpoint to be triggered only the first time the specified function is called, one can use the 'One shot' option :  

![One Shot Breakpoint](Screenshots/oneshot.jpg?raw=true "one shot kernel breakpoint")  

The configuration file allows for any number of breakpoints to be set as well as defining specific conditions which have to be met for the breakpoint to be triggered :  

```xml
<BP function="" min_counter="1" max_counter="0" is_oneshot="0" msg="" isactive="0"/>
```

The min_counter and max_counter options refer to the global counter of function called by the supervised call.  
It is possible to trigger a breakpoint after and/or before a specified number of function called, for instance :  

```xml
<BP function="NtCreateThreadEx" min_counter="150" max_counter="500" is_oneshot="0" msg="" isactive="0"/>
```

A breakpoint will be triggered for any call to NtCreateThreadEx occuring after the 150th supervised function call and before the 500th function call.  
This type of condition can be used after having run the sample at least a first time to get an idea of its execution flow.  
In a later release, it should be possible to set breakpoint based on the value of the parameters of the targeted function.  

The msg option simply offers the possibility to display a custom message to the kernel debugger when the breakpoint is triggered.  
It could be for instance instructions on how to manually proceed to obtain a specific result in the state the supervised code is when the breakpoint is triggered.  

* Ignoring software breakpoint (int 3, 0xcc)

This is a small feature which allows to prevent user software breakpoints to be forwarded to the kernel debugger when they are located in specific parts of the memory of a supervised process.  
I designed this feature for a sample that was using 0xCC as an anti-debug gimmick  

GUI:  
![Ignoring user sofware breakpoint](Screenshots/ignorecc.jpg?raw=true "Ignore 0xcc") 

Conf:  

```xml
<IGNORE_USER_CC_BREAKPOINTS isactive="0">
	<IGNORE_FROM_EXE isactive="0"/>
	<IGNORE_FROM_DLL isactive="0"/>
	<IGNORE_FROM_MEMORY isactive="0"/>
	<IGNORE_FOR_ALL_PROCESSES isactive="0"/>
</IGNORE_USER_CC_BREAKPOINTS>
```


## Remote Execution <a name="remote_execution"></a>  

GUI:  
![Remote Execution](Screenshots/remote_exec.jpg?raw=true "Remote Execution") 

Conf:  
```xml
<REMOTE_EXECUTION>
	<SUPERVISE_REMOTE_THREADS isactive="0"/>
	<MONITOR_CHILD_PROCESS isactive="0"/>
	<CLONE_OPEN_PROCESS isactive="0"/>
</REMOTE_EXECUTION>
```
