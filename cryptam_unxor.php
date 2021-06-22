<?PHP
/*
 * v2.0 Jun 1 2016
 * cryptam_unxor.php: tyLabs.com Cryptam - command line script
 * unxor and unrol
 */
    
$key = '';
$rol = 0;
$not = 0;
$outfile = '';

//accept a file as input
if (is_file($argv[1])) {
	$outfile = $argv[1].".out";
	for ($i = 2; $i < $argc; $i+=2) {
		if ($argv[$i] == "-xor" && is_file($argv[$i+1]) )
			$key = file_get_contents($argv[$i+1]);
		else if ($argv[$i] == "-xor" || $argv[$i] == "-key")
			$key = $argv[$i+1];
		else if ($argv[$i] == "-rol")
			$rol = $argv[$i+1];
		else if ($argv[$i] == "-out")
			$outfile = $argv[$i+1];
		else if ($argv[$i] == "-not") {
			$not = 1;
			$i--;
		}
	}
} else {
	echo "php cryptam_unxor.php virus.doc -xor fe85aa -rol 3 -not -out file.out\n";
	exit(1);
}

$data = file_get_contents($argv[1]);

if ($key != '') {
	$data = xorString($data, hex2str($key));
}

if ($rol != 0 ) {
	$data = cipherRol($data, $rol);
}

if ($not != 0) {
	$data = cipherNot($data);
}

file_put_contents($outfile, $data);


function hex2str($hex) {
	$str = '';
	for($i = 0; $i<strlen($hex); $i += 2) {
		$str .= chr(hexdec(substr($hex,$i,2)));
	}
	return $str;
}

function cipherRol($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++){
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, $x).substr($bin, 0, $x);
 		$newstring .= chr(bindec($ro));
    }
    return $newstring;
}

function cipherNot($string) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = '';
		for ($j = 0; $j < 8; $j++) {
			if ($bin[$j] == 1)
				$ro .= 0;
			else
				$ro .= 1;
		}
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}

function xorString($data, $key) {
	$key_len = strlen($key);
	$newdata = '';
 
	for ($i = 0; $i < strlen($data); $i++) {
        	$rPos = $i % $key_len;
		$r = '';
		if ($key_len == 1) 
			$r = ord($data[$i]) ^ ord($key);
		else
			$r = ord($data[$i]) ^ ord($key[$rPos]);
 
		$newdata .= chr($r);
	}
 
	return $newdata;
}


?>