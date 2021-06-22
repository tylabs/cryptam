<?PHP
/*
 * v2.0 Jan 30 2019
 * cryptam-sig.php: tyLabs.com Cryptam - signatures
 * 
 */

$global_cryptam_engine = $global_engine = 83;


$cryptam_executable_sigs = array(
'This program cannot be run in DOS mode'=>'string.This program cannot be run in DOS mode', 
'This program must be run under Win32'=>'string.This program must be run under Win32',
hex2bin("2070726F6772616D002063616E6E6F74200062652072756E2069006E20444F53206D6F") =>'string.RTL.This program cannot be run in DOS mode', 
'LoadLibraryA'=>'string.LoadLibraryA', 
'GetModuleHandleA'=>'string.GetModuleHandleA', 
'GetCommandLineA'=>'string.GetCommandLineA', 
'GetSystemMetrics'=>'string.GetSystemMetrics', 
'GetProcAddress'=>'string.GetProcAddress', 
'CreateProcessA'=>'string.CreateProcessA', 
'URLDownloadToFileA'=>'string.URLDownloadToFileA', 
'EnterCriticalSection'=>'string.EnterCriticalSection', 
'GetEnvironmentVariableA'=>'string.GetEnvironmentVariableA',
'CloseHandle'=>'string.CloseHandle',
'CreateFileA'=>'string.CreateFileA',
'URLDownloadToFileA'=>'string.URLDownloadToFileA',
'Advapi32.dll'=>'string.Advapi32.dll',
'RegOpenKeyExA'=>'string.RegOpenKeyExA',
'RegDeleteKeyA'=>'string.RegDeleteKeyA',
'user32.dll'=>'string.user32.dll',
'shell32.dll'=>'string.shell32.dll',
'KERNEL32'=>'string.KERNEL32',
'ExitProcess'=>'string.ExitProcess',
'GetMessageA'=>'string.GetMessageA',
'CreateWindowExA'=>'string.CreateWindowExA',
hex2bin('504500004C010100')=> 'string.PE Header',
'hTsip orrgmac naon tebr nui  nOD Somed' => 'string.transposition cipher of This program cannot be run in DOS mode',
'edom SOD ni nur eb tonnac margorp sihT' => 'string.reverse This program cannot be run in DOS mode',
//hex2bin('A2434B9B0183937B3B930B6B011B0B73737BA301132B0193AB73014B7301227A9A016B7B232B') => 'string.cipher of This program cannot be run in DOS mode',
//hex2bin('627B0B23624B13930B93CB0A') => 'string.cipher of LoadLibraryA',
//hex2bin('3A2BA382937B1B0A2323932B9B9B') => 'string.cipher of GetProcAddress',
//hex2bin('2AC34BA382937B1B2B9B9B') => 'string.cipher of ExitProcess',
'/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h'=>'string.MacOSX10.5.sdk',
'__gcc_except_tab__TEXT'=>'string._gcc_except_tab__TEXT',
'/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices'=>'string.CoreServices.framework',
'/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'=>'string.CoreFoundation.framework',
'@_getaddrinfo'=>'string.etaddrinfo',
'@_pthread_create'=>'string.pthread_create',
'StartupParameters.plist'=>'string.StartupParameters.plist',
'dyld__mach_header'=>'string.dyld__mach_header',
'/usr/lib/libSystem'=>'string./usr/lib/libSystem',
'/usr/lib/dyld'=>'string./usr/lib/dyld',
'__PAGEZERO'=>'string.__PAGEZERO',
'/usr/lib/libgcc_s'=>'string./usr/lib/libgcc_s',
'<key>RunAtLoad</key>'=>'string.RunAtLoad',
'__mh_execute_header'=>'string.__mh_execute_header',
'impersonationLevel=impersonate' => 'string.vbs impersonationLevel',
'On Error Resume Next' => 'string.vbs On Error Resume Next',
//'nOE rrroR semu eeNtx' => 'string.vbs.transposition cipher of On Error Resume Next',
'WScript.CreateObject("WScript.Shell")' => 'string.vbs WScript',
'CreateObject("Scripting.FileSystemObject")' => 'string.vbs CreateObject',
);


$cryptam_plaintext_sigs = array (
'w:ocx w:data="DATA:application/x-oleobject'=>'exploit.office OLE application command',
'Scripting.FileSystemObject' => 'exploit.office embedded Visual Basic write to file Scripting.FileSystemObject',
'Wscript.Shell' => 'exploit.office embedded Visual Basic execute shell command Wscript.Shell',
'OpenTextFile' => 'exploit.office embedded Visual Basic accessing file OpenTextFile',
'netsh firewall set opmode mode=disable' => 'exploit.office shell command netsh disable firewall',
'ScriptBridge.ScriptBridge.1' => 'exploit.office ScriptBridge may load remote exploit',
'cmd.exe ' => 'exploit.office cmd.exe shell command',
'powershell.exe ' => 'exploit.office powershell.exe shell command',
'-w hidden -encodedcommand' => 'exploit.office powershell obfuscated command',

hex2bin("0600DDC6040011000100D65A12000000000001000000060000000300") => 'exploit.office smarttag overflow CVE-2006-2492',
hex2bin("0600C8BE1B0008000200685B1200") => 'exploit.office smarttag overflow CVE-2006-2492',
'\x4F\x72\x69\x65\x6E\x74\x61\x74\x69\x6F\x6E.\x50\x4F\x33(.{1}?)' => 'exploit.office excel buffer overflow CVE-2009-3129',
'\x66\x55\x66\x55.{3}?\x00\x43\x57\x53' => 'suspicious.flash CWS flash in MS Office document',
'\x66\x55\x66\x55.{3}?\x00\x46\x57\x53' => 'suspicious.flash FWS flash in MS Office document',
'\x66\x55\x66\x55.{3}?\x00\x5a\x57\x53' => 'suspicious.flash ZWS flash in MS Office document',
'CONTROL ShockwaveFlash.ShockwaveFlash' => 'suspicious.flash flash control in MS Office document',
hex2bin("076A69745F656767") => 'suspicious.flash jit_egg',
hex2bin('4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134') => 'flash.exploit CVE-2011-0609 A',

hex2bin('7772697465427974650541727261799817343635373533304143433035303030303738') => 'flash.exploit CVE-2011-0611 B', 
hex2bin('5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348') => 'flash.exploit CVE-2011-0611 C',
hex2bin('343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431') => 'flash.exploit CVE-2011-0611 D',

hex2bin('3063306330633063306330633063306306537472696E6706') => 'flash.exploit CVE-2011-0611 E', 
hex2bin('410042004300440045004600470048004900A18E110064656661756C74') => 'flash.exploit CVE-2011-0611 F', 
hex2bin('00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277') => 'flash.exploit CVE-2011-0611 G', 
hex2bin('34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235') => 'flash.exploit CVE-2011-0609 B', 
hex2bin('3941303139413031394130313941303139064C6F61646572') => 'flash.exploit CVE-2011-0609 C', 

'AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB' => 'flash.exploit CVE-2011-0611 A',

hex2bin("537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E") => 'exploit.flash flash calling malformed MP4 CVE-2012-0754 A',
'sn .{1,300}?pFragments.{1,700}?sv .{1,200}?[a-zA-Z0-9\*\+]{50}' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333',
'\sn\*\sn-pFragments' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 B',

'pFragments.{1,200}?\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x0D\x0A' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 B',

'sn pfragments.{1,30}?11111111' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 C',

'sn[\W]{1,20}?pFragments' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 D',

'\\sn9pFRagMEnTS' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 F',


//'objdata.{1,350}?5\w*3\w*4\w*3\w*6\w*F\w*6\w*D\w*6\w*3\w*7\w*4\w*6\w*C\w*4\w*C\w*6\w*9\w*6\w*2\w*2\w*E\w*4\w*C' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 A',


'objdata.{1,100}?53436F6D63746C4C69622E4C' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 B',




'objdata.{1,300}?\w*5\w*0\w*6\w*1\w*6\w*3\w*6\w*b\w*6\w*1\w*6\w*7\w*6\w*5\w*0\w*0' => 'exploit.office RTF embedded file package',

'ListView2, 1, 1, MSComctlLib, ListView' => 'exploit.office CVE-2012-0158 C',

'ListView1, 1, 0, MSComctlLib, ListView' => 'exploit.office CVE-2012-0158 G',

'CONTROL MSComctlLib.Toolbar.2' => 'exploit.office MSCOMCTL.OCX Toolbar MS12-060 A',
'Toolbar1, 0, 0, MSComctlLib, Toolbar' => 'exploit.office MSCOMCTL.OCX Toolbar MS12-060 B',

'MSComctlLib.Toolbar.2' => 'exploit.office MSCOMCTL.OCX Toolbar MS12-060',

'4D53436F6D63746C4C69622E546F6F6C6261722E32' => 'exploit.office RTF MSCOMCTL.OCX Toolbar MS12-060 C',


'0000000000000000000000000000000000000000000000.{1,300}?49746D736400000002000000010000000C000000436F626A' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 D',

'MSComctlLib.ListViewCtrl.{1,25}?objdata' => 'exploit.office CVE-2012-0158 E',

'MSComctlLib.ListViewCtrl.2' => 'exploit.office CVE-2012-0158 F',

'\x4C\x00\x69\x00\x73\x00\x74\x00\x56\x00\x69\x00\x65\x00\x77\x00\x41' => 'exploit.office CVE-2012-0158 F',


'\xEC\xBD\x01\x00\x05\x00\x90\x17\x19\x00\x00\x00\x08\x00\x00\x00\x49\x74\x6D\x73\x64\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x0C\x00\x00\x00\x43\x6F\x62\x6A.\x00\x00\x00\x82\x82\x00\x00\x82\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.{4}?\x90' => 'exploit.office OLE MSCOMCTL.OCX RCE CVE-2012-0158 H',

'\x31\x31\x31\x31\x31\x31\x31\x31\x31\x0D\x0D\x0D\x13\x20\x43\x4F\x4E\x54\x52\x4F\x4C\x20\x4D\x53\x43\x6F\x6D\x63\x74\x6C\x4C\x69\x62\x2E\x4C\x69\x73\x74\x56\x69\x65\x77\x43\x74\x72\x6C\x2E\x32.{1}?' => 'exploit.office OLE MSCOMCTL.OCX RCE CVE-2012-0158 I',

hex2bin('4D006900630072006F0073006F0066007400200042006100730065002000430072007900700074006F0067007200610070006800690063002000500072006F0076006900640065007200200076') => 'suspicious.office encrypted document',

hex2bin('45006E006300720079007000740065006400530075006D006D006100720079') => 'suspicious.office encrypted document',


'\x45\x78\x61\x6D\x70\x6C\x65\x0B\x63\x72\x65\x61\x74\x65\x4C\x69\x6E\x65\x73\x09\x68\x65\x61\x70\x53\x70\x72\x61\x79\x08\x68\x65\x78\x54\x6F\x42\x69\x6E\x07\x6D\x78\x2E\x63\x6F\x72\x65\x0A\x49\x46\x6C\x65\x78\x41\x73\x73\x65\x74\x09\x46\x6F\x6E\x74\x41\x73\x73\x65\x74\x0A\x66\x6C\x61\x73\x68\x2E\x74\x65\x78\x74.{1}?'  => 'flash.exploit CVE-2012-1535',

'\x45\x4D\x42\x45\x44\x44\x45\x44\x5F\x43\x46\x46\x0A\x66\x6F\x6E\x74\x4C\x6F\x6F\x6B\x75\x70\x0D\x45\x6C\x65\x6D\x65\x6E\x74\x46\x6F\x72\x6D\x61\x74\x08\x66\x6F\x6E\x74\x53\x69\x7A\x65\x0B\x54\x65\x78\x74\x45\x6C\x65\x6D\x65\x6E\x74\x07\x63\x6F\x6E\x74\x65\x6E\x74\x0E\x63\x72\x65\x61\x74\x65\x54\x65\x78\x74\x4C\x69\x6E\x65\x08\x54\x65\x78\x74\x4C\x69\x6E\x65\x01\x78\x01\x79\x06\x68\x65\x69\x67\x68\x74\x08\x61\x64\x64\x43\x68\x69\x6C\x64\x06\x45\x6E\x64\x69\x61\x6E\x0D\x4C\x49\x54\x54\x4C\x45\x5F\x45\x4E\x44\x49\x41\x4E\x06\x65\x6E\x64\x69\x61\x6E\x22\x30\x63\x30\x63\x30\x63\x30\x63.{1}?' => 'flash.exploit CVE-2012-1535',

'MSComctlLib.TabStrip' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856',
'4d53436f6d63746c4c69622e546162537472697' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856 hex',
'9665fb1e7c85d111b16a00c0f0283628' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856 A',

'\x8A\x23\xAB\xA7\x8A\x01\x90\x8B\x23\xEE\xD4\x61\xD8\x87\x23\x96\xA3\x9A\x02\xF4\x85\x23\xA1\xF9\x4A\xB4\x83\x23\xFB\xE0\xE3\x03.{1}?'  => 'flash.exploit CVE-2013-0634 memory corruption',

'\x77\x72\x69\x74\x65\x44\x6F\x75\x62\x6C\x65\x08\x4D\x61\x74\x72\x69\x78\x33\x44\x06\x4F\x62\x6A\x65\x63\x74\x0B\x66\x6C\x61\x73\x68\x2E\x6D\x65\x64\x69\x61\x05\x53\x6F\x75\x6E\x64\x0C\x66\x6C\x61\x73\x68\x2E\x73\x79\x73\x74\x65\x6D\x0C\x43\x61\x70\x61\x62\x69\x6C\x69\x74\x69\x65\x73\x07\x76\x65\x72\x73\x69\x6F\x6E\x0B\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65\x10\x77\x69\x6E.{1}?'  => 'flash.exploit CVE-2012-5054 Matrix3D',

'\x73\x00\x74\x00\x64\x00\x6F\x00\x6C\x00\x65\x00\x32\x00\x2E\x00\x74\x00\x6C\x00\x62\x00\x23\x00\x4F\x00\x4C\x00\x45\x00\x20\x00\x41\x00\x75\x00\x74\x00\x6F\x00\x6D\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E.{1}?' => 'suspicious.office Visual Basic macro',

'D27CDB6E-AE6D-11CF-96B8-444553540000' => 'suspicious.office embedded Flash in MSO file',
'978C9E23-D4B0-11CE-BF2D-00AA003F40D0' => 'exploit.office MSO MSCOMCTL.OCX RCE CVE-2012-0158 I',
'BDD1F04B-858B-11D1-B16A-00C0F0283628' => 'exploit.office MSO MSCOMCTL.OCX RCE CVE-2012-0158 J',
'C74190B6-8589-11D1-B16A-00C0F0283628' => 'exploit.office MSO MSCOMCTL.OCX RCE CVE-2012-0158 K',
'996BF5E0-8044-4650-ADEB-0B013914E99C' => 'exploit.office MSO MSCOMCTL.OCX RCE CVE-2012-0158 L',
'9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E' => 'exploit.office MSO MSCOMCTL.OCX RCE CVE-2012-0158 M',

'\\7300740056006\\' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 obs A',
'4C69{\\*}7374566' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 obs B',
'4C0069007300740056006900650077004' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 obs C',

'4BF0D1BD8B85D111B16A00C0F0283628' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 obs D',

hex2bin('4BF0D1BD8B85D111B16A00C0F0283628') => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 obs E',

'{\\*}' => 'suspicious.office RTF obfuscation using empty comments',

'COMCTL.TreeCtrl.1' => 'exploit.office MSCOMCTL.OCX RCE CVE-2012-0158 TreeCtrl.1',
'434F4D43544C2E547265654374726C2E31' => 'exploit.office MSCOMCTL.OCX RCE CVE-2012-0158 hex TreeCtrl.1',

'MSComctlLib.TreeCtrl.2' => 'suspicious.office ActiveX content TreeCtrl.2',
'4D53436F6D63746C4C69622E547265654374726C2E32' => 'suspicious.office ActiveX content TreeCtrl.2',
'B69041C78985D111B16A00AA003F40D0' => 'suspicious.office ActiveX content TreeCtrl.2 clsid',
'C74190B6-8589-11D1-B16A-00AA003F40D0' => 'suspicious.office ActiveX content TreeCtrl.2 clsid',
'C74190B6-8589-11D1-B16A-00C0F0283628' => 'suspicious.office ActiveX content TreeCtrl.1 clsid',
'B69041C78985D111B16A00C0F0283628' => 'suspicious.office ActiveX content TreeCtrl.1 clsid',

'\x90\x90\x90\x90\xEB\x7F\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x24\x90\x90\x90\x90.{1}?' => 'suspicious.office heap spray',

'\x49\x49\x2A\x00\xC8\x49\x00\x00\x80\x3F\xE0\x50\x38\x24\x16\x0D\x07\x84\x42\x61\x50\xB8\x64\x36\x1D\x0F\x88\x44\x62\x51\x38\xA4\x56\x2D\x17\x8C\x46\x63\x51\xB8\xE4\x76\x3D\x1F\x90\x48\x64\x52\x39\x24\x18\x01\x27\x94\x49\x65\x52\xB9\x64\xB6\x5D\x2F\x98\x4C\x66\x53\x39\xA4\xD6\x6D\x37\x9C\x4E\x67\x53\xB9\xE4\xF6\x7D\x3F\xA0\x50\x68\x54\x3A\x25\x16\x8D\x47\xA4\x52\x69\x54\xBA\x65\x36\x1D\x28\x94\xD3\xAA\x55\x3A\xA5\x56\xAD\x57\xAC\x56\x6B\x55\xBA\xE5\x76\xBD\x5F\xB0\x58\x6C\x56\x3B\x25\x96\xCD\x67\xB2\x54\x24\xF6\x8B\x65\xB6\xDD\x6F\xB8\x5C\x6E\x57\x3B\xA5\xD6\xED\x77\xBC\x5E\x6F\x57\xBB\xE5\xF6\x47\x51\xBF\x60\x70\x58\x3C\x26\x17\x0D\x87\xC4\x62\x71\x58\xBC\x66\x37\x1D\x8F\xA5\xDA\x80\x19\x0C\xA6\x57\x2D\x97\xCC\x66\x73\x59\xBC\x54\x04\x80\x3F\xE0\x50\x38\x24\x16\x0D\x07\x84\x42\x61\x50\xB8\x64\x36\x1D\x0F\x88\x44\x62\x51.{1}?' => 'exploit.office TIFF CVE-2013-3906 A ',

'\x49\x49\x2a\x00\x08\x00\x00\x00\x02\x00\x0e\x01\x02\x00\xfc\x3a\x00\x00\x26\x00\x00\x00\x69\x87\x04\x00\x01\x00\x00\x00\x22\x3b\x00\x00\x7c\x5a\x00\x00\x0a\x0a\x0a\x0a\x0a.{1}?' => 'exploit.office TIFF CVE-2013-3906 B',


'\x5C\x73\x6E\x34\x09\x6D\x65\x6E\x74\x73.{1}?' => 'exploit.office CVE-2010-3333 E',
'1EFB6596-857C-11D1-B16A-00C0F0283628' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856 classid',

'\objclass Word.Document'  => 'obfuscation.office RTF embedded Word Document',

'objclass MSComctlLib.ImageComboCtl.2' => 'suspicious.office RTF MSCOMCTL.OCX ImageComboCtl',

'MSComctlLib.ImageComboCtl.2' => 'suspicious.office MSCOMCTL.OCX ImageComboCtl',


'\x00MSComctlLib.ImageComboCtl.{1}?' => 'suspicious.office OLE MSCOMCTL.OCX ImageComboCtl',

hex2bin('49006D0061006700650043006F006D0062006F00430074006C002000') => 'suspicious.office OLE MSCOMCTL.OCX ImageComboCtl wide',

'listoverridecount([1-9]{2}?|0[0-9]{2})' => 'exploit.office RTF memory corruption listoverridecount CVE-2012-2539 CVE-2014-1761',

'\listoverridecount25' => 'exploit.office RTF memory corruption listoverridecount CVE-2014-1761',

'jpegblip.{1,20}?49492a00cf660000ffff' => 'exploit.office RTF TIFF CVE-2013-3906 A',

'\.inf\x00.{1,64}?\[Version' => 'exploit.office OLE INF CVE-2014-4114 C, CVE-2014-6352 C',

'\x00\\\\.{1,64}?\.inf\x00' => 'exploit.office remote INF CVE-2014-4114 A',

'7EBEFBC0-3200-11d2-B4c2-00A0C9697D17' => 'exploit.office OLE INF CVE-2014-4114 B, CVE-2014-6352 A',

'0003000C-0000-0000-c000-000000000046' => 'suspicious.office Packager ClassID used by CVE-2014-6352 A',

'0c00030000000000c000000000000046' => 'suspicious.office Packager ClassID used by CVE-2014-6352 B',

hex2bin('0c00030000000000c000000000000046') => 'suspicious.office Packager ClassID used by CVE-2014-6352 C',

//hex2bin('5000610063006B00610067006500720020005300680065006C006C0020004F0062006A006500630074') => 'exploit.office OLE CVE-2014-6352 G',

'"Packager Shell Object"' => 'suspicious.office OOXML Class used by CVE-2014-6352 D',

hex2bin('6100750074006F006F00700065006E') => 'exploit.office VB Macro auto execute',

'MSScriptControl.ScriptControl' => 'suspicious.script potential active content',

'"ADODB.Recordset"' => 'exploit.office Local Zone Remote Exec CVE-2015-0097',


'CDDBCC7C-BE18-4A58-9CBF-D62A012272CE' => 'exploit.office Sandbox Overflow class id CVE-2015-1770',

'CDDBCC7CBE184A589CBFD62A012272CE' => 'exploit.office Sandbox Overflow class CVE-2015-1770',

hex2bin('CDDBCC7CBE184A589CBFD62A012272CE') => 'exploit.office Sandbox Overflow class CVE-2015-1770',

'Control.TaskSymbol.1' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

'MMC.IconControl.1' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

'44f9a03b-a3ec-4f3b-9364-08e0007f21df' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

'b0395da5-6a15-4e44-9f36-9a9dc7a2f341' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',
'44f9a03ba3ec4f3b936408e0007f21df' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

'b0395da56a154e449f369a9dc7a2f341' => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

hex2bin('44f9a03ba3ec4f3b936408e0007f21df') => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

hex2bin('b0395da56a154e449f369a9dc7a2f341') => 'exploit.office Task Symbol buffer overflow CVE-2015-2424',

'forall.{1,30}?1145324612' => 'exploit.office PostScript CVE-2015-2545',

'forall.{1,30}?integertype' => 'exploit.office PostScript CVE-2015-2545',

'&#xBD50;&#x7C38;' => 'exploit.office SmartTag element parsing CVE-2015-1641',
'&#xBD68;&#x7C38;' => 'exploit.office SmartTag element parsing CVE-2015-1641',
'FFFFFFFF0F29010105060000001014140A140E40012940A0042958FFFFFFFF' => 'exploit.flash Type Confusion CVE-2016-4117',

'h\x00t\x00t\x00p.{300,400}?\x20\x69\x33\x25\xF9\x03\xCF\x11\x8F\xD0\x00\xAA\x00\x68\x6f\x13' => 'exploit.office Packager htmlfile remote inclusion CVE-2017-0199',

'68007400740070.{600,700}?20693325f903cf118fd000aa00686f13' => 'exploit.office Packager htmlfile remote inclusion CVE-2017-0199',

'Target.{1,5}?script:' => 'exploit.office PPSX Script Moniker CVE-2017-0199 CVE-2017-8570',
'\x19\x7f\xd2\x11\x97\x8e\x00\x00\xf8\x75\x7e\x2a.{8}?w\x00s\x00d\x00l\x00' => 'exploit.office SoapMoniker CVE-2017-8759',

hex2bin('0003000000000000C000000000000046') => 'suspicious.office OLE2Link',

'0003000000000000C000000000000046' => 'suspicious.office OLE2Link',
'instrText>DDE' => 'suspicious.office DDE Excel execution',
'DDE ' => 'suspicious.office DDE Excel execution',
'DDEAUTO' => 'suspicious.office DDE Excel execution',
'"DDE"' => 'suspicious.office DDE Excel execution',

'idmap\/>\s+?<\/o:OLEObject>' => 'exploit.office nested font confusion CVE-2017-11826',

'classid="{00000000-0000-0000-0000-000000000001}"' => 'suspicious.office activex potential heapspray',

'<ax:ocx ax:classid' => 'suspicious.office activeX',

hex2bin('4141120C4300') => 'Equation editor buffer overflow CVE-2017-11882',

'4141120C4300' => 'Equation editor buffer overflow CVE-2017-11882 hex',

'E0C9EA79F9BACE118C8200AA004BA90B' => 'Moniker exploit MSHTML CVE-2018-8174 hex',
hex2bin('E0C9EA79F9BACE118C8200AA004BA90B') => 'Moniker exploit MSHTML CVE-2018-8174',
'<vt:lpstr>script:' => 'suspicious.office xml script',


);



?>
