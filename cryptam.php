<?PHP
/*
 * v2.0 Jun 1 2016
 * cryptam.php: tyLabs.com Cryptam - command line script
 * Main script to call for document analysis command line usage: 
 * php cryptam.php <filename> [data element to display/defaults to
 * all when blank]
 */


$global_magic_file = "file"; //magic file
$global_yara_cmd = '/opt/local/bin/yara';
$global_yara_sig = '';
$global_imphash = ''; //path to python and extras/imphash.py - requires pefile
	//example = '/usr/bin/python /home/malware/pefile/pefile-1.2.10-139/imphash.py';

ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_COMPILE_ERROR|E_ERROR|E_CORE_ERROR);


include_once('cryptam-lib.php');
include_once('cryptam-cli.php');

set_time_limit(0);





if (!isset($cryptam_executable_sigs)) {
	echo "ERROR: Signatures not found. cryptam-sig.php missing or corrupt.\n";
	exit(0);
}



if (!isset($argv[1])) {
	echo "Specify a file or directory.\n";
	exit(0);
}

date_default_timezone_set('America/Toronto');

$jsonout = 0;

$options = getopt("y:vpj", array("json","yara:","yarasig:","version","info","paranoid"));

if (isset($options['j']) || isset($options['json']) )
	$jsonout = 1;
if (isset($options['y']))
	$global_yara_sig = $options['y'];
if (isset($options['yarasig']))
	$global_yara_sig = $options['yarasig'];
if (isset($options['yara']))
	$global_yara_cmd = $options['yaracmd'];
if (isset($options['p']))
	$global_paranoid = 1;
if (isset($options['paranoid']))
	$global_paranoid = 1;


if (isset($options['version']) || isset($options['v']) || isset($options['info'])) {
	echo "cryptam.php <options> <file or dir>\n";
	if (!isset($global_engine) ) {
		echo "ERROR: Signatures not found.\n";
		exit(1);
	} 

	echo "Command line options:\n";
	echo "#####################\n";
	echo "  -y or --yarasig filename : Yara signature file\n";
	echo "  -yara command : Path to yara command\n";
	echo "  -p / --paranoid : More exhaustive XOR search. Samples entropy areas from mid/end of file.\n";
	echo "  -v / --version / -info : print version info and help\n";
	echo "  -j / --json  : print results as json\n";

	echo "\n";
	echo "Detection engine: $global_engine\n";
	echo "Embedded executable signatures: ".count($cryptam_executable_sigs)."\n";
	echo "Exploit signatures: ".count($cryptam_plaintext_sigs)."\n";
}

$file = array();
$dir = array();
$opt = array();
for ($i = 1; $i < $argc; $i++) {
	if ($argv[$i] == "-y" || $argv[$i] == "--yara" || $argv[$i] == "--yarasig" ) {
		$i++;
	} else if ($argv[$i] == "-v" || $argv[$i] == "--version" || $argv[$i] == "--info" || $argv[$i] == "-j" ||$argv[$i] == "--json") {
		continue;
	} else if (is_file($argv[$i])) {
		$file[$argv[$i]] = 1;
	} else if (is_dir($argv[$i])) {
		$dir[$argv[$i]] = 1;
	} else
		$opt[$argv[$i]] = 1;
}

foreach ($file as $f => $x) {

	$result = analyseDoc($f);

	if (isset($result['yara']) && is_array($result['yara'])) {
		$yara = '';
		foreach($result['yara'] as $sig) {
			if ($sig != '')
				$yara .= "$sig\n";
		}
		$result['yara'] = $yara;
	}
			

	if (count($opt) > 0) {
		foreach ($opt as $o => $y) {
			if (isset($result[$o])) {
				if ($argc > 2)
					echo $o."=";
				if (!is_array($result[$o]))
					echo $result[$o]."\n";
				else {
					foreach ($result[$o] as $item) {
						echo "$item\n";
					}
				}

			}
		}
	} else {
		if (isset($result['h_distribution'])) unset($result['h_distribution']);
		if (isset($result['h_dispersion'])) unset($result['h_dispersion']);

		if ($jsonout != 1) 
			print_r($result);
		else {
			echo json_encode($result, JSON_PRETTY_PRINT);
		}
	}
}

foreach ($dir as $d => $z) {
  if (false !== ($listing = scandir($d))) {
    foreach ($listing as $id => $file) {
        if ($file != "." && $file != ".." && $file != ".DS_Store" && is_file($d."/".$file) && 
		strtolower(end(explode(".", $file))) != 'txt' && 
		strtolower(end(explode(".", $file))) != 'php') {
			if ($jsonout != 1) 
				echo $d."/".$file."\n";
			$result =  analyseDoc($d."/".$file);
			if (isset($result['yara']) && is_array($result['yara'])) {
				$yara = '';
				foreach($result['yara'] as $sig) {
					if ($sig != '')
						$yara .= "$sig\n";
				}
				$result['yara'] = $yara;
			}

		if (count($opt) > 0) {
			foreach ($opt as $o => $y) {
				if (isset($result[$o])) {
					if ($argc > 2)
						echo $o."=";
					if (!is_array($result[$o]))
						echo $result[$o]."\n";
					else {
						foreach ($result[$o] as $item) {
							echo "$item\n";
						}
					}
	
				}
			}
		} else {
			if (isset($result['h_distribution'])) unset($result['h_distribution']);
			if (isset($result['h_dispersion'])) unset($result['h_dispersion']);
		
			if ($jsonout != 1) 
				print_r($result);
			else
				echo json_encode($result, JSON_PRETTY_PRINT);
		}
        }
    }
  }
    closedir($handle);
}



function logdebug($string) {
	//echo $string."\n";
}
function logverbose($string) {
	//echo $string."\n";
}



?>
