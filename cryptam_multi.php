<?PHP
/*
 * v2.0 Jun 1 2016
 * cryptam_unxor.php: tyLabs.com Cryptam - command line script
 * unxor and unrol, get parameters from api, extract embedded exe, docs and pdfs
 */
    

$key = '';
$rol = 0;
$ror = 0;
$tph = 0;
$tp = 0;
$xorla = 0;
$xorst = 0;
$not = 0;
$rtl = 0;
$zero = 0;
$offset = 0;
$submit = 0;
$api = 0;
$start = '';
$stkey = '';
$xorth = 0;

$outfile = '';

//accept a file as input
if (isset($argv[1]) && is_file($argv[1])) {
	$outfile = $argv[1].".out";
	for ($i = 2; $i < $argc; $i+=2) {
		if ($argv[$i] == "-xor" && is_file($argv[$i+1]) )
			$key = file_get_contents($argv[$i+1]);
		else if ($argv[$i] == "-xor" || $argv[$i] == "-key")
			$key = $argv[$i+1];
		else if ($argv[$i] == "-rol")
			$rol = $argv[$i+1];
		else if ($argv[$i] == "-offset")
			$offset = $argv[$i+1];
		else if ($argv[$i] == "-ror")
			$ror = $argv[$i+1];
		else if ($argv[$i] == "-out")
			$outfile = $argv[$i+1];
		else if ($argv[$i] == "-zero") { //bitwise not
			$zero = 1;
			$i--;
		} else if ($argv[$i] == "-rtl") { //bitwise not
			$rtl = 1;
			$i--;
		} else if ($argv[$i] == "-not") { //bitwise not
			$not = 1;
			$i--;
		} else if ($argv[$i] == "-xorla") { //xor look ahead
			$xorla = 1;
			$i--;
		} else if ($argv[$i] == "-xorst") { //xor stretch
			$xorst = 1;
			$start = $argv[$i+1];
			$stkey = $argv[$i+2];
			$i++;
		} else if ($argv[$i] == "-xorth") { //xor thin
			$xorth = 1;
			$start = $argv[$i+1];
			$stkey = $argv[$i+2];
			$i++;
		} else if ($argv[$i] == "-tph") { //transposition
			$tph = 1;
			$i--;
		} else if ($argv[$i] == "-tp") { //transposition
			$tp = 1;
			$i--;
		} else if ($argv[$i] == "-submit") { //transposition
			$submit = 1;
			$i--;
		} else if ($argv[$i] == "-api") { //transposition
			$api = 1;
			$i--;
		}
	}
	$md5 = md5_file($argv[1]);
} else {
	echo "Cryptam Multi Tool - Decode and extract embedded executables from documents\n";
	echo "php cryptam_unxor.php virus.doc -xor fe85aa -rol 3 -not -out file.out\n";
	echo "php cryptam_unxor.php virus.doc -api [gets decoding params from malwaretracker.com]\n";
	echo "php cryptam_unxor.php virus.doc -submit [upload file to malwaretracker.com, download params]\n";

	echo "Params:
     -xor <key>   XOR key to decode document with
     -rol <int>   bitwise left shift <int> places
     -ror <int>   bitwise right shift <int> places
     -not         use a bitwise not filter
     -zero        don't replace zeros in single byte xor decode
     -xorla       xor look ahead cipher
     -xorst       xor stretch cipher <start hex> <increment hex>
     -xorth       xor thin cipher <start hex> <increment hex>
     -tp          transposition cipher filter on file
     -tph         transposition cipher filter on EXE 512 byte header
     -rtl         right to left NTLZ1 decompress (platform independent)
     -submit      upload file to malwaretracker.com Cryptam analyzer, captures decoding params
                  and extracts EXE/docs/pdfs from file
     -api         queries malwaretracker.com Cryptam api with MD5 hash only, captures decoding params
                  and extracts EXE/docs/pdfs from file
";


	exit(1);
}

if ($submit == 1) {
	echo "Submitting ".$argv[1]." to remote server\n";
	$result = unserialize(mwtdocfile($argv[1]));
	if (isset($result['has_exe']) ) {
		$ror = $result['key_rol'];
		$key = $result['key'];
		$tp = $result['key_tp'];
		$tph = $result['key_tph'];
		$xorla = $result['key_la'];
		$not = $result['key_not'];
		$zero = $result['key_zero'];
	}
}

if ($api == 1) {
	
	echo "Accessing remote API for decoding params for $md5\n";
	$result = unserialize(mwtdocreport($md5));
	if (isset($result['has_exe']) ) {
		$ror = $result['key_rol'];
		$key = $result['key'];
		$tp = $result['key_tp'];
		$tph = $result['key_tph'];
		$xorla = $result['key_la'];
		$not = $result['key_not'];
		$zero = $result['key_zero'];
	}
}


$data = file_get_contents($argv[1], false, null, $offset);

if ($key != '') {
	echo "using XOR key $key";
	if ($zero != 0)
		echo " (-zero)";
	echo "\n";
	$data = xorString($data, hex2str($key), $zero);

}

if ($xorst != 0  && $xorst != '') {
	echo "using xor stretch decoder\n";
	$data = xorStretch($data,hex2str($start), hex2str($stkey));
}


if ($xorth != 0  && $xorth != '') {
	echo "using xor thin decoder\n";
	$data = xorThin($data,hex2str($start), hex2str($stkey));
}

if ($xorla != 0  && $xorla != '') {
	echo "using xor look ahead decoder\n";
	$data = xorAheadString($data);
}

if ($rol != 0 && $rol != '') {
	echo "using ROL $rol\n";
	$data = cipherRol($data, $rol);
}

if ($ror != 0  && $ror != '') {
	echo "using ROR $ror\n";
	$data = cipherRor($data, $ror);
}

if ($not != 0 && $not != '') {
	echo "using bitwise not\n";
	$data = cipherNot($data);
}

if ($tp != 0  && $tp != '') {
	echo "using transposition decoder\n";
	$data = untranspose($data);
}


if ($rtl != 0  && $rtl != '') {
	echo "decompress with RTL NTLZ1\n";
	$data = dCompressBuf($data);
}


if ($tph != 0  && $tph != '') {
	echo "note first 512 bytes of EXE may be transpositioned\n";
}

if (md5($data) != $md5) //don't rewrite unfiltered file
	file_put_contents($outfile, $data);


dump_pe($data, $argv[1], $tph);


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

function cipherRor($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, -$x).substr($bin, 0, -$x);
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}

function xorAheadString($data) {
	$newdata = '';
 
	for ($i = 0; $i < strlen($data)-1; $i++) {
 		$r =  ord($data[$i]) ^ ord($data[$i+1]);
 		$newdata .= chr($r);
	}
 
	return $newdata;
}

function untranspose($string) {

	$newstring = '';
	for ($i = 0; $i < strlen($string); $i+=2){
 		$newstring .= $string[$i+1].$string[$i];
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

function xorString($data, $key, $zero = 0) {
	$key_len = strlen($key);
	$newdata = '';
 
	for ($i = 0; $i < strlen($data); $i++) {
        	$rPos = $i % $key_len;
		$r = '';
		if ($key_len == 1) {
			if ($zero == 1) {
				if ($data[$i] != "\x00")
					$r = ord($data[$i]) ^ ord($key);
				else
					$r = ord($data[$i]);
			} else 
				$r = ord($data[$i]) ^ ord($key);
		} else
			$r = ord($data[$i]) ^ ord($key[$rPos]);
 
		$newdata .= chr($r);
	}
 
	return $newdata;
}


//one byte key only
function xorStretch($data, $start, $key) {
	$newdata = '';
	$k = $start;

	for ($i = 0; $i < strlen($data); $i++) {
		$r = '';
		
		if ($data[$i] != "\x00" && $data[$i] != $k) {
			$r = ord($data[$i]) ^ ord($k);
			$k = chr(0xFF & (ord($k) + ord($key)));//ord($key)
		} else
			$r = ord($data[$i]);
			
		
		$newdata .= chr($r);
	}
 
	return $newdata;
}


//one byte key only
function xorThin($data, $start, $key) {
	$newdata = '';
	$k = $start;

	for ($i = 0; $i < strlen($data); $i++) {
		$r = '';	
		$r = ord($data[$i]) ^ ord($k);		
		$k = chr(0xFF & (ord($k) + ord($key)));
		$newdata .= chr($r);
	}
 
	return $newdata;
}



function mwtdocfile($file, $email = '', $message = ''){
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, "http://www.malwaretracker.com/docapi.php");
	curl_setopt($curl, CURLOPT_POST, true);
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_HEADER, 0); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API C 1.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$data = array( "sample[]"=> "@$file", 'type' => 'cryptam', 'private' => '1');
	if ($message != '')
		$data['message'] = $message;
	if ($email != '')
		$data['email'] = $email;

	curl_setopt($curl, CURLOPT_POSTFIELDS, $data); 
	$response = curl_exec($curl);
	$err = curl_error($curl); 
	if ($err != '') {
		return "CURLERROR: $err"; 
	}
	curl_close ($curl);
	return $response;
}


function mwtdocreport($hash, $type='cryptam'){
	$curl = curl_init();
	$url =  "http://www.malwaretracker.com/docapirep.php?hash=$hash&type=$type";
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_POST, 0);
	curl_setopt($curl, CURLOPT_HEADER, 0);
	curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:'));
	curl_setopt($curl, CURLOPT_VERBOSE, 0);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); 
	curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;) MWT API C 1.0");

	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1); 
	$result = curl_exec($curl); 
	$err = curl_error($curl); 
	if ($err != '') {
		return "CURLERROR: $err"; 
	}
	curl_close ($curl);
	return $result;
}

/* //START GPL 2 Clause Licensed Code

# Derived 2013 Jun 19 from https://github.com/MITRECND/chopshop/blob/ec2cfee02517e8442226cfdd020211b9de929880/ext_libs/lznt1.py

# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Ported to PHP and modified by Malware Tracker Limited
# Copyright (c) 2013 Malware Tracker Limited. All rights reserved.
# v1.0
*/


function dCompressBlock($x) {
	$size = strlen($x);
	$u = '';
	$j=0;
	while (strlen($x)>0) {
		$p = ord($x[0]);
		if ($p == 0) {// These are symbol are tokens
			$u .= substr($x, 1, 8);
			$x = substr($x, 9);
		} else {  // There is a phrase token
			$idx = 8;
			$x = substr($x, 1);
			while ($idx>0 && strlen($x) >0) { 
				$ustart = strlen($u);
				if (($p & 1)!=1) {
					$u .= $x[0];
					$x = substr($x,1);
				} else {
					if (strlen($x) < 2) break;
	            			$xa = unpack('S', substr($x,0,2));
					$pt = $xa[1];
					$pt = $pt & 0xffff;
					$i = (strlen($u)-1); // Current Pos
					$l_mask = 0xfff;
					$p_shift = 12;
					while ($i >= 0x10) {
						$l_mask >>= 1;
						$p_shift -= 1;
						$i >>= 1;
					}
					$length = ($pt & $l_mask) + 3;
					$bp = ($pt  >> $p_shift) + 1;

                    			if ($length >= $bp) {
  						$tmp = substr($u, -$bp);
						while ($length >= strlen($tmp) && strlen($tmp) > 0) {
							$u .= $tmp;										$length -= strlen($tmp);
						}
						$u .= substr($tmp, 0, $length);
					} else {
						$insert = substr($u, -$bp, $length);							$u .= $insert;
					}
					$x = substr($x, 2);
				}
				$p >>= 1;
				$idx -= 1;
			}
		}
	}
    return $u;
}

//RTLDecompress() Windows ntdll NTLZ1 decompress
function dCompressBuf($blob){
	$good = true;
	$unc = '';


	if (strlen($blob) == 0) return $unc;
	while ($good &&  strlen($blob) >= 2) {

		$hdr = substr($blob, 0, 2);
		$blob = substr($blob, 2);
		$lena = unpack('S', $hdr);
		$length = $lena[1];
 
		$length &= 0xfff;
		$length += 1;
		if ($length > strlen($blob)) {
			//echo "invalid block len";
			$good = False;
		} else {
			$y = substr($blob, 0, $length);
			$blob = substr($blob, $length);
			$unc .= dCompressBlock($y);
		}
		if ($good == False)
			return $unc;
	}

	return $unc;
}
//END GPL 2 Clause Licensed Code


function dump_pe($data, $filename, $tph = 0, $parent='') {
	global $global_imphash;
	$file_headers =  array("MZ(.{1,150}?)This program" => "exe",
		"ZM(.{1,150}?)hTsip orrgmac" => "exe",
		'\xCA\xFE\xBA\xBE' => "macho",
		'\xCE\xFA\xED\xFE' => "macho",
		'\x7F\x45\x4C\x46' => "elf",
		'\x7B\x5crt' => "rtf",
		'.vbs\x00' => "vbs",
		'\x25\x50\x44\x46' => "pdf",
		//'\x00\x00\x50\x4B\x03\x04\x14\x00\x06\x00' => "docx",
		'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' => "doc",
		'\x0A\x25\x25\x45\x4F\x46\x0A' => "eof",
		'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A' => "eof",
		'\x0D\x25\x25\x45\x4F\x46\x0D' => "eof");

	$addresses = array();		
	$files = array();

	foreach($file_headers as $search => $ext) {
		preg_match_all("/$search/is", $data, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[0][0])) {
			foreach($match[0] as $matches0) {
				if (isset($matches0[1])) {
					
					$l = $matches0[1];
					//echo "$l is $ext\n";
					if (strstr($search, '?') !== FALSE && $ext == 'eof') {
						$ladd = preg_replace("/\\x./", '', $search);
						$l += strlen($ladd);
					}
					if ($ext == "docx")
						$l += 2;
					if ($ext == "vbs")
						$l += 5;
					$addresses[$l] = array('loc' => $l, 'searchtype' => 'regex', 'ext' => $ext);

					
				}
			}

		}

	}

	//back into the right order
	ksort($addresses, SORT_NUMERIC);

	$last = '-1';
	$over = 0;
	foreach ($addresses as $loc => $hit) {
		if ($last >= 0) {
			$addresses[$last]['end'] = $loc;
			
		}
	
		if ($last >= 0 && $addresses[$last]['ext'] != 'eof' && $hit['ext'] == 'eof') {
		 	unset($addresses[$loc]);
			$over = 1;
		} else {
			$last = $loc;
			$over = 0;
		}
	}
	if ($over == 0) {
		$addresses[$last]['end'] = strlen($data);
	}

	//var_dump($addresses);

	$files = array();
	foreach ($addresses as $loc => $hit) {
		if (isset($hit['ext']) && $hit['ext'] != 'eof' && isset($hit['end']) ) {
			//echo "$loc and $parent\n";
			if ($loc == 0 && $parent == '')
				continue;

		
			//untranspose needed
			$dropfile = $filename."-".$loc.".".$hit['ext'];
			if ($hit['ext'] == "exe") $dropfile .= ".virus";

			$fp = fopen($dropfile, "w");
			$filedata = substr($data, $loc, $hit['end']-$loc);
			if (($tph == 1 && substr($filedata, 0, 2) == "ZM") || ($hit['ext'] == "vbs" && substr($filedata, 0, 20) == "nOE rrroR semu eeNtx")) {
				//echo "untransposing first 512 bytes at $loc\n";
				$filenew = untranspose(substr($filedata, 0, 512)).substr($filedata, 512);
				$filedata = $filenew;
			}
			
			$imphash = '';
			$fmd5 = md5($filedata);
			$fsha1 = sha1($filedata);
			$fsha256 = hash('sha256', $filedata);
			$fsha512 = hash('sha512', $filedata);
			fwrite($fp, $filedata);
			fclose($fp);
			if ($hit['ext'] == "exe" && $global_imphash != '')
				$imphash = exec($global_imphash." ".$dropfile);
			
			$files[$loc] = array('len' => ($hit['end']-$loc), 'ext' => $hit['ext'], 'md5' => $fmd5,
			'sha1' => $fsha1, 'sha256' => $fsha256, 'sha512' => $fsha512, 'filename' => $filename."-".$loc.".".$hit['ext']);
			if (strlen($imphash) == 32)
				$files[$loc]['imphash'] = $imphash;

			//echo "wrote ".($hit['end']-$loc)." bytes at $loc as type ".$hit['ext']." $fmd5\n";
		}
	}
	return $files;
}




?>