# Configuration File  

Beeing a sandbox as much as a debugging assisting tool, Reflexions can be configured to collect or ignore specific events during analysis as well as alter the supervised code behavior.  
The configuration is therefore meant to be malware specific, in most cases the analyst will run his sample a first time, analyze the logs and fine tune the configuration.  
The configuration can then be reused for any analysis of a sample of the same malware family or be shared along an analyzed sample to enable other analyst to replicate the same result.  

As it stands right now, Reflexions GUI only offers some of the features offered by the configuration file  

<details>
  <summary>
    	Empty configuration file sample
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

## Target

![Target](Screenshots/target.jpg?raw=true "Target")  

