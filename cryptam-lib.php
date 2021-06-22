<?PHP
/*
 * v2.0 May 17 2018
 * cryptam-slib.php: tyLabs.com Cryptam - engine
 * main analysis engine
 */

ini_set('pcre.backtrack_limit', 10000000);
ini_set('pcre.recursion_limit', 10000000);
ini_set('memory_limit', '1512M');



$global_true_keys = array('00fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a898887868584838281807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a696867666564636261605f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201',
'f4f3f2f182868b9aecebeae99a8e8392e4e3e2e192b6bbaadcdbdad9aabeb3a2d4d3d2d1a2a6abbacccbcac9baaea3b2c4c3c2c1b2d6dbcabcbbbab9caded3c2b4b3b2b1c2c6cbdaacabaaa9dacec3d2a4a3a2a1d2f6fbea9c9b9a99eafef3e294939291e2e6ebfa8c8b8a89faeee3f284838281f2161b0a7c7b7a790a1e13027473727102060b1a6c6b6a691a0e03126463626112363b2a5c5b5a592a3e33225453525122262b3a4c4b4a493a2e23324443424132565b4a3c3b3a394a5e53423433323142464b5a2c2b2a295a4e43522423222152767b6a1c1b1a196a7e73621413121162666b7a0c0b0a097a6e63720403020172969b8afcfbfaf98a9e9382',
'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
'a7a6a5a4a3a2a1a05f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241407f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463624b601f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201003f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0fffefdd6fbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8',
'8485868798999a9b9c9d9e9f9091929394959697e8e9eaebecedeeefe0e1e2e3e4e5e6e7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7d8d9dadbdcdddedfd0d1d2d3d4d5d6d728292a2b2c2d2e2f202122232425262738393a3b3c3d3e3f303132333435363708090a0b0c0d0e0f000102030405060718191a1b1c1d1e1f101112131415161768696a6b6c6d6e6f606162636465666778797a7b7c7d7e7f707172737475767748494a4b4c4d4e4f404142434445464758595a5b5c5d5e5f5051525354555657a8a9aaabacadaeafa0a1a2a3a4a5a6a7b8b9babbbcbdbebfb0b1b2b3b4b5b6b788898a8b8c8d8e8f80818283');

if (!function_exists('hex2bin')) {
	function hex2bin($h) {
		if (!is_string($h))
			return null;
		$r='';
		$len = strlen($h);
		for ($a=0; $a<$len; $a+=2) {
			if ($a+1 < $len)
				$r.=chr(hexdec($h{$a}.$h{($a+1)}));
		}
	  	return $r;
	}
}

include_once('cryptam-sig.php');


function validateFileType($filename) {
	global $global_magic_file;
	$content_type_arr = '';
	if ($global_magic_file != '')
		$content_type_arr = explode(': ', exec("$global_magic_file ".escapeshellarg($filename)));
	if (isset($content_type_arr[1]))
		$content_type = $content_type_arr[1];
	else
		$content_type = "data";

	$content = file_get_contents($filename);
	if (stristr($content_type, 'executable') || (substr($content, 0, 2) == "PK" && !strstr($content, '[Content_Types].xml') )) //META-INF/MANIFEST
		return -1;

	return 0;
}

function getFileType($filename) {
	global $global_magic_file;
	$content_type_arr = explode(': ', exec("$global_magic_file ".escapeshellarg($filename)));
	if (isset($content_type_arr[1]))
		$content_type = $content_type_arr[1];
	else
		$content_type = 'data';

	return $content_type;
}


function getFileMetadata($filename) {
	global $global_magic_file;
	exec("$global_magic_file ".escapeshellarg($filename), $file_arr2);
	$file_arr = implode("\n", $file_arr2);
	$file = explode( ', ', $file_arr);
	$out = '';
	for($i = 2; $i < count($file); $i++) {
		$out .= $file[$i]."\n";
	}
	return $out;
}


//alt quick scan - do read of 256 block and throw away when 50% or more is zero, or all blocks are FF, or 20.
function ingestData($data, $try_len=1024, &$blocks='') {
	$table = array();

	//build data structure
	for ($i = 0; $i < $try_len; $i++) {
		$table[$i] = array();
	}

	$j = 0;

	$blocking = array();
	$b = 0;

	$distribution = array();
	//echo "Filesize: ".strlen($data)."\n";


	//collect data
	for ($i = 0; $i < strlen($data); $i++) {
		if (isset($distribution[ord($data[$i])]) )
			$distribution[ord($data[$i])] += 1;
		else
			$distribution[ord($data[$i])] = 1;

		if ($i == 0 || $i % $try_len == 0) {
			//echo "special 1 $i\n";
			$sff = 0;
			$s20 = 0;
			$s00 = 0;
			$sas = 0;
			$top = $i+$try_len;
			if ($top > strlen($data))
				$top = strlen($data);
			for ($k = $i; $k < $top; $k++) {
				$cur = ord($data[$k]);
				//echo "[$k $cur]\n";
				if ($cur == 0) {
					$s00++;
					
				} else if ($cur == 20) {
					$s20++;
					
				} else if ($cur == 255) {
					$sff++;
				} else if (ctype_print($data[$k])) {
					$sas++;
				}
			}
			if ($s00 -4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($sff-4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($s20-4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($sas-4 > $try_len*0.98) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else {
   				if ($j == $try_len) {
					$j = 0;
					$blocking[$b] = 1;
					$b++;
				}
				$cur = ord($data[$i]);
		//echo "$j $i\n";
				if (isset($table[$j][$cur]))
					$table[$j][$cur] += 1;
				else
					$table[$j][$cur] = 1;
	

				//echo "$i $j\n";
				$j++;
			}
			//echo "special 2\n";

		} else {

   			 if ($j == $try_len) {
				$j = 0;
				$b++;
				$blocking[$b] = 1;
			}
			$cur = ord($data[$i]);
		//echo "$j $i $cur ".$data[$i]."\n";
			if (isset($table[$j][$cur]))
				$table[$j][$cur] += 1;
			else
				$table[$j][$cur] = 1;
	
			$j++;
			//echo "$i $j\n";
			
		}
		

	}

	//show distribution
	//echo "Blocking\n";
	$h = 0;
	$h2 = 0;
	$blocks = '';
	foreach ($blocking as $block => $stat) {
		$blocks .= $stat;
		if ($stat == 1)
			$h++;
		else {
			if ($h > $h2)
				$h2 = $h;
			$h = 0;
		}

	}
	if ($h > $h2)
		$h2 = $h;
	//echo "\n End blocking $h\n";
	//echo "blocking $h2\n";

	//sort by occurences
	for ($i = 0; $i < $try_len; $i++) {
		arsort($table[$i]);
	}

	//var_dump($table); 

	$table['distribution'] = $distribution;
	return $table;
}




function topHits($array = array(), $max_len = 5) {

	$len = count($array);

	if ($len > $max_len) $len = $max_len;

	$total = 0;
	$cur = 0;

	foreach($array as $char => $hits) {
		$total += $hits;
		$cur++;
		if ($cur == $len) break;
	}

	$table = array();
	$cur = 0;
	$i = 0;
	foreach($array as $char => $hits) {
		//$table[$char] = number_format($hits/$total *100,2);
		$table[$i] = array ($char => number_format($hits/$total *100,2), 'hits' => $hits, 'char' => $char, 'percent' => number_format($hits/$total *100,2), 'total' =>$total);

		$cur++;
		if ($cur == $len) break;
		$i++;
	}

	return $table;

}


function analyseByte($table, $need_len) {
	$cur_len = count($table);



	if ($cur_len != $need_len)
		$byte = realignTable($table, $need_len);
	else
		$byte = $table;


	//echo "Analyse byte: $need_len, $cur_len, ".count($byte)."\n";




	$final = array();
	//$misses = 0;
	$rank = 0;
	//echo "\n==== $need_len =====\n";
	for ($i = 0; $i < $need_len; $i++) {
		$top = topHits($byte[$i], 5);

		//echo "\n[@".dechex($i)."]\n";
		if (isset($top[0]) && isset($top[1])) {
			if (dechex($top[0]['char']) == '00' || dechex($top[0]['char']) == '0' || dechex($top[0]['char']) == '20')
				$final[$i] = array('key_rank' => 0, 'char' => $top[0]['char'], 'percent' => '0');		
			else {
				$final[$i] = array('key_rank' => number_format((($top[0]['percent']-$top[1]['percent'])/10),0), 'char' => $top[0]['char'],
						'hits' => $top[0]['hits'], 'total' => $top[0]['total'], 'percent' => $top[0]['percent'], 'next' => $top[1]['char'], 'next_hits'=> $top[1]['hits']);
			}
			/*echo "\n$i RANK ".$final[$i]['key_rank']."\n";
			foreach($top as $loc => $topar) {
				echo "$loc ".dechex($topar['char'])." ".$topar['hits']." ".$topar['percent']."\n";
			
			}*/
			$rank += $final[$i]['key_rank'];
		
		} else if (isset($top[0])) {
			if (dechex($top[0]['char']) == '00' || dechex($top[0]['char']) == '0' || dechex($top[0]['char']) == '20')
				$final[$i] = array('key_rank' => 0, 'char' => $top[0]['char'], 'percent' => '');		
			else {
				$final[$i] = array('key_rank' => 10, 'char' => $top[0]['char'],
						'hits' => $top[0]['hits'], 'total' => $top[0]['total'], 'percent' => $top[0]['percent']);
			}
		}
		
	}
	//echo "Misses $misses\n";
	//echo "Rank $rank\n";
	$final['key_rank'] = $rank;
	return $final;
}



function realignTable($table, $to_len) {

	$from_len = count($table);
	echo "realign from $from_len to $to_len\n";
	$table_new = array();

	//build data structure
	for ($i = 0; $i < $to_len; $i++) {
		$table_new[$i] = array();
	}

	$j = 0;

	//collect data
	for ($i = 0; $i < $from_len; $i++) {
		foreach($table[$i] as $char => $hits) {
			if (!isset($table_new[$j][$char]))
				$table_new[$j][$char] = $hits;
			else
				$table_new[$j][$char] += $hits;
		}
		$j++;
   		if ($j == $to_len)
			$j = 0;

	}


	//sort by occurences
	for ($i = 0; $i < $to_len; $i++) {
		arsort($table_new[$i]);
	}

	return $table_new;
}



function stringScan($data) {


	$md5 = md5($data);
	$sha1 = sha1($data);
	$sha256 = hash("sha256", $data);

	$exploits = ptScanString($data);
	$rank = $exploits['rank'];
	unset($exploits['rank']);
	$pt = $exploits['pt'];
	logdebug("pt $pt");
	unset($exploits['pt']);
	$summary = '';
	$severity = 0;

	foreach ($exploits as $l => $hit) {
		if (isset($hit['exploit']) && $hit['exploit'] != '') {
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			if (preg_match("/exploit\./", $hit['hit_desc'], $match))
				$severity += 20;
			else
				$severity += 2;
		}
	}

 
	if ($severity > 0) {
		return array('is_malware' => 1, 'severity' => $severity, 'key_len' => 0, 'key' => '',
			'exploits' => $exploits, 'md5' => $md5, 'sha1' => $sha1, 'sha256' => $sha256, 'summary' => $summary, 'has_exe' => 0);

	} else {
		return array('is_malware' => 0, 'severity' => $severity, 'key_len' => 0, 'key' => '','md5' => $md5, 'sha1' => $sha1, 'sha256' => $sha256, 'summary' => $summary, 'has_exe' => 0);
	}
}


//this gets top matches in most crypto files, some cases get less matches than expected ref ef403a0c255d83b45b0c14c43e214f7d
//could add 1024 range to statistical anlysis and check for 256 or smaller keys...
function cryptoStat($data, $try_len=4) {


	$md5 = md5($data);
	$sha1 = sha1($data);
	$sha256 = hash("sha256", $data);


	//check blocking for parts of file with high entropy
	$blocks = '';
	$table = ingestData($data, 1024, $blocks);

	$distribution = $table['distribution'];
	unset ($table['distribution']);

	//var_dump($distribution);

	$exploits = ptScanFile($data);
	//var_dump($exploits);
	$rank = $exploits['rank'];
	unset($exploits['rank']);
	$pt = $exploits['pt'];
	logdebug("pt $pt");
	unset($exploits['pt']);
 	$is_malware = 0;

	if ($rank > 0) {
		//echo "DETECTED MALWARE RANK $rank plaintext\n";
		$is_malware = 1;
		//return array('is_malware' => 1, 'key_len' => 0, 'key' => '',
		//	'exploits' => $exploits);
	}

	//paranoid scan - continue past here
	if ($pt > 0) {
		return array('is_malware' => 1, 'key_len' => 0, 'key' => '',
			'exploits' => $exploits, 'md5' => $md5, 'sha1' => $sha1, 'sha256' => $sha256);
	}


	//echo "rank=$rank\n";

	$res = analyseByte($table, 1024);//1024
	//echo count($res)."\n";

	//var_dump($res);

		


	if (isset($res['key_rank']) && $res['key_rank'] > 100) {
		//echo "DETECTED MALWARE RANK ".$res['key_rank']." encrypted\n";
		$is_malware = 1;
	} else if (isset($res['key_rank']) && $res['key_rank'] >= 1) {
		//echo "suspicious RANK ".$res['key_rank']." encrypted\n";
		$is_malware = 1;
	} else if (isset($res['key_rank']) && $is_malware != 1) {
		//echo "CLEAN RANK ".$res['key_rank']."\n";
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');
	} else  if ($is_malware != 1) {
		//echo "CLEAN\n";
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');
	}
	//var_dump($res);

	if ($is_malware == 1) {
		$scan = findKey($res);

		if ($scan['key'] != '') {
			$scan['key_occ'] = substr_count($data,hex2bin($scan['key']));
			$scan['key_entropy'] = checkEntropy($scan['key']);
			$scan['key_hash'] = md5(normalizeKey($scan['key']));

		} else
			$scan['key_len'] = 0;


		$scan['key_rank'] = $res['key_rank'];
		$scan['is_malware'] = 1;
		$scan['key_blocks'] = $blocks;
		$scan['md5'] = $md5;
		$scan['sha1'] = $sha1;
		$scan['sha256'] = $sha256;
		$scan['exploits'] = $exploits;
		$scan['h_distribution'] = '';
		$topd = 0;
		for ($i = 0; $i < 256; $i++) {
			if (isset($distribution[$i])) {
				$scan['h_distribution'] .= $distribution[$i].",";
				if ($distribution[$i] > $topd)
					$topd = $distribution[$i];
			} else
				$scan['h_distribution'] .= "0,";
		}
		$scan['h_distribution'] .= "$topd,"; //ceiling item

		$scan['h_dispersion'] = '';
		for ($i = 0; $i < count($res)-1; $i++) {
			if (isset($res[$i]['char'])) {
				$scan['h_dispersion'] .= $res[$i]['char'].",".$res[$i]['percent'].",";
			} else
				$scan['h_dispersion'] .= "0,0,";

		}



		if ($scan['key'] == 00) {
				//check for encrypted FF space where an embedded .doc file is encrypted and whitespace is not encoded
				preg_match_all("/[\\00]{400}.{70,80}\\x00\\x00\\x00[^\\00]{1}\\x00\\x00\\x00(.{432})/s", rtrim($data), $match, PREG_OFFSET_CAPTURE);

				//var_dump($matches);
				if (isset($match[1][0])) {
					foreach($match[1] as $matches0) {
						if (isset($matches0[1])) {
							$l = $matches0[1];
							$len = strlen($matches0[0]);
							$extract = strhex($matches0[0]);
							$mentropy = checkEntropy($extract);
							//echo "found @ $l $len bytes of potential cipher text with entropy $mentropy\n";
							if ($mentropy > 90.0 && $l > 512) {
								//echo $extract."\n";
								$bytes = 0;

								if (substr_count($extract,substr($extract, 0, 2)) >= 430) {
									//echo "one byte\n";
									$bytes = 1;
	
								} else if (substr_count($extract,substr($extract, 0, 4)) >= 215) {
									//echo "two byte\n";
									$bytes = 2;

								} else if (substr_count($extract,substr($extract, 0, 6)) >= 144) {
									//echo "three byte\n";
									$bytes = 3;

								} else if (substr_count($extract,substr($extract, 0, 8)) >= 102) {
									//echo "four byte\n";
									$bytes = 4;

								} else if (substr_count($extract,substr($extract, 0, 10)) >= 82) {
									//echo "four byte\n";
									$bytes = 5;
								} else if (substr_count($extract,substr($extract, 0, 12)) >= 68) {
									//echo "four byte\n";
									$bytes = 6;
								} else if (substr_count($extract,substr($extract, 0, 14)) >= 55) {
									//echo "four byte\n";
									$bytes = 7;
								} else if (substr_count($extract,substr($extract, 0, 16)) >= 50) {
									//echo "eight byte\n";
									$bytes = 8;
	
								} else if (substr_count($extract,substr($extract, 0, 32)) >= 25) {
									//echo "sixteen byte\n";
									$bytes = 16;

								} else if (substr_count($extract,substr($extract, 0, 64)) >= 11) {
									//echo "thirtytwo byte\n";
									$bytes = 32;

								} else if (substr_count($extract,substr($extract, 0, 128)) >= 4) {
									//echo "64 byte\n";
									$bytes = 64;

								} else if (substr_count($extract,substr($extract, 0, 256)) >= 3) {
									//echo "128 byte\n";
									$bytes = 128;

								} else if (substr($extract, 0, 352) == substr($extract, 513, 352 )) {	
									
									//echo "256 byte\n";
									$bytes = 256;

								}
								if ($bytes > 0) {
									$key = substr($extract, 0, $bytes*2);
									//echo "key length = $bytes\n";
									//echo "key=$key\n";
									//echo "correcting for FF space key leak with bitwise not\n";
									$key = strhex(cipherNot(hex2str($key)));
									//echo "corrected key=$key\n";
									$keyloc = $l;
									$offset = $l % $bytes;
									//echo "key offset $offset for $l\n";
									if ($offset != 0)
										$key = substr($key, -$offset*2).substr($key, 0, ($bytes-$offset)*2);
									//echo "location corrected key=$key\n";

		
									$scan['key'] = $key;
									$scan['key_occ'] = substr_count($data,hex2bin($scan['key']));
									$scan['key_entropy'] = checkEntropy($scan['key']);
									$scan['key_hash'] = md5(normalizeKey($scan['key']));
									$scan['key_zero'] = 1;
									$scan['key_len'] = $bytes;
									$scan['key_rank'] = 256;
									$scan['is_malware'] = 1;
								}
							}
						}
					}
				}
		}


		return $scan;
			
	} else {
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');



	}
	


}


function keyPivot($key, $len) {

	$data = array();
	if ($len == strlen($key))
		return $key;


	$j = 0;
	for($i = 0; $i < strlen($key); $i+=2) {
		if ($j % $len == 0) $j = 0;
		$char = hexdec($key[$i].$key[$i+1]);
		if (!isset($data[$j]) )
			$data[$j] = array();
		else if (isset($data[$j][$char]) )
			$data[$j][$char] += 1;
		else
			$data[$j][$char] = 1;
		$j++;
	}
	for ($i = 0; $i < $len; $i++) {
		if (isset($data[$i]) && is_array($data[$i]))
			arsort($data[$i]);
	}
	$newkey = '';

	for ($i = 0; $i < $len; $i++) {
		if (isset($data[$i]) && is_array($data[$i])) {
			foreach ($data[$i] as $c => $h) {
				if ($h == 1) {
					$newkey .= "00";
				} else {
					$hex = dechex($c);
						if (strlen($hex) == 1)
							$hex = "0".$hex;
					$newkey .= $hex;
				}
				break;
			}
		}
	}

	//echo "$newkey\n";
	return $newkey;
}



function findKey($res) {
		$extract = '';
		$bytes = 1024;
		foreach ($res as $pos => $data) {

			if ("$pos" != 'key_rank') {
				//echo $data['char'];
				$hex = dechex($data['char']);
				if (strlen($hex) == 1)
					$hex = "0".$hex;
				$extract .= $hex;
			}

		}


		$top256 = keyPivot($extract,256);


		$keyRefactoring = array(
			'1' => array('key' => keyPivot($extract,1)),
			'2' => array('key' => keyPivot($extract,2)),
			'3' => array('key' => keyPivot($extract,3)),
			'4' => array('key' => keyPivot($extract,4)),
			'5' => array('key' => keyPivot($extract,5)),
			'6' => array('key' => keyPivot($extract,6)),
			'7' => array('key' => keyPivot($extract,7)),
			'8' => array('key' => keyPivot($extract,8)),
			'16' => array('key' => keyPivot($extract,16)),
			'32' => array('key' => keyPivot($extract,32)),
			'64' => array('key' => keyPivot($extract,64)),
			'128' => array('key' => keyPivot($extract,128)),
			'256' => array('key' => $top256),
			'512' => array('key' => substr($extract, 0, 1024)),
			'1024' => array('key' => $extract),
			);


		foreach ($keyRefactoring as $kl => $k) {
			if ($k['key'] == '')
				$keyRefactoring[$kl]['similar'] = 0;
			else 
				$keyRefactoring[$kl]['similar'] = substr_count($extract,$k['key']);
			$keyRefactoring[$kl]['percent'] = $keyRefactoring[$kl]['similar'] * $kl / 1024 * 100;
			//echo "$kl extract $extract\n";
			//echo "similar ".$keyRefactoring[$kl]['similar']."\n";
			//echo "key ".$k['key']."\n";
			//echo "percent ".$keyRefactoring[$kl]['percent']."\n\n";
			
		}

		$keyRefactoring['256a'] = array('key' => $top256, 'similar' => similar_text($top256,substr($extract, 0, 512)));
		$keyRefactoring['256a']['percent'] = $keyRefactoring['256a']['similar'] / 512 * 100;
		$keyRefactoring['256b'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 512, 512)));
		$keyRefactoring['256b']['percent'] = $keyRefactoring['256b']['similar'] / 512 * 100;
		$keyRefactoring['256c'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 1024, 512)));
		$keyRefactoring['256c']['percent'] = $keyRefactoring['256c']['similar'] / 512 * 100;
		$keyRefactoring['256d'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 1536, 512)));
		$keyRefactoring['256d']['percent'] = $keyRefactoring['256d']['similar'] / 512 * 100;
		$keyRefactoring['512']['similar'] = similar_text(substr($extract, 0, 1024), substr($extract, 1025, 1024));
		$keyRefactoring['512']['percent'] = $keyRefactoring['512']['similar'] / 1024 * 100;
		//var_dump($keyRefactoring);
		logdebug(print_r($keyRefactoring, TRUE));

		/*if ($keyRefactoring['2']['similar'] >= 250) {
			//echo "two byte\n";
			$bytes = 2;

		} else if ($keyRefactoring['3']['similar'] >= 200) {
			//echo "three byte\n";
			$bytes = 3;

		} else if ($keyRefactoring['4']['similar'] >= 100) {
			//echo "four byte\n";
			$bytes = 4;
		} else if ($keyRefactoring['5']['similar'] >= 80) {
			//echo "four byte\n";
			$bytes = 5;
		} else if ($keyRefactoring['6']['similar'] >= 80) {
			//echo "four byte\n";
			$bytes = 6;
		} else if ($keyRefactoring['7']['similar'] >= 70) {
			//echo "four byte\n";
			$bytes = 7;
		} else if ($keyRefactoring['8']['similar'] >= 60) {
			//echo "eight byte\n";
			$bytes = 8;

		} else if ($keyRefactoring['16']['similar'] >= 40) {
			//echo "sixteen byte\n";
			$bytes = 16;

		} else if ($keyRefactoring['32']['similar'] >= 20) {
			//echo "thirtytwo byte\n";
			$bytes = 32;

		} else if ($keyRefactoring['64']['similar'] >= 10) {
			//echo "64 byte\n";
			$bytes = 64;

		} else if ($keyRefactoring['128']['similar'] >= 5) {
			//echo "128 byte\n";
			$bytes = 128;

		} else if ($keyRefactoring['256a']['similar'] > 417 ||
			$keyRefactoring['256b']['similar'] > 417 ||
			$keyRefactoring['256c']['similar'] > 417 ||
			$keyRefactoring['256d']['similar'] > 417) {	
			
			//echo "256 byte\n";
			$bytes = 256;

		} else if ($keyRefactoring['1']['similar'] >= 375) {
			//echo "one byte\n";
			$bytes = 1;

		} else if ($keyRefactoring['512']['similar'] > 1000 ) {
			//echo "512 byte\n";
			$bytes = 512;

		} else {
			//echo "1024 byte\n";
			$bytes = 1024;
		}*/

		//changing to percent rankings on Mar 26 2015

		if ($keyRefactoring['2']['percent'] >= 90) {
			//echo "two byte\n";
			$bytes = 2;

		} else if ($keyRefactoring['3']['percent'] >= 90) {
			//echo "three byte\n";
			$bytes = 3;

		} else if ($keyRefactoring['4']['percent'] >= 90) {
			//echo "four byte\n";
			$bytes = 4;
		} else if ($keyRefactoring['5']['percent'] >= 90) {
			//echo "four byte\n";
			$bytes = 5;
		} else if ($keyRefactoring['6']['percent'] >= 90) {
			//echo "four byte\n";
			$bytes = 6;
		} else if ($keyRefactoring['7']['percent'] >= 90) {
			//echo "four byte\n";
			$bytes = 7;
		} else if ($keyRefactoring['8']['percent'] >= 90) {
			//echo "eight byte\n";
			$bytes = 8;

		} else if ($keyRefactoring['16']['percent'] >= 90) {
			//echo "sixteen byte\n";
			$bytes = 16;

		} else if ($keyRefactoring['32']['percent'] >= 90) {
			//echo "thirtytwo byte\n";
			$bytes = 32;

		} else if ($keyRefactoring['64']['percent'] >= 90) {
			//echo "64 byte\n";
			$bytes = 64;

		} else if ($keyRefactoring['128']['percent'] >= 90) {
			//echo "128 byte\n";
			$bytes = 128;

		} else if ($keyRefactoring['256a']['percent'] > 90 ||
			$keyRefactoring['256b']['percent'] > 90 ||
			$keyRefactoring['256c']['percent'] > 90 ||
			$keyRefactoring['256d']['percent'] > 90) {	
			
			//echo "256 byte\n";
			$bytes = 256;

		} else if ($keyRefactoring['1']['percent'] >= 90) {
			//echo "one byte\n";
			$bytes = 1;

		} else if ($keyRefactoring['512']['percent'] >= 90 ) {
			//echo "512 byte\n";
			$bytes = 512;

		} else {
			//echo "1024 byte\n";
			$bytes = 1024;
		}


	if ($bytes == 2 && $keyRefactoring['2']['key'][0].$keyRefactoring['2']['key'][1] == $keyRefactoring['2']['key'][2].$keyRefactoring['2']['key'][3])
		$bytes = 1;

	if ($bytes == 1024)
		return array('key_len' => $bytes, 'key' => $extract);

	return array('key_len' => $bytes, 'key' => $keyRefactoring[$bytes]['key']);
	
}

function checkEntropy($str) {
	$cnt = 0;
	for ($i = 0; $i < strlen($str); $i+=2) {
		if ($str[$i] == "0" && $str[$i+1] == "0")
			$cnt++;
	}
	//echo "$cnt\n";
	return (1-($cnt/(strlen($str)/2))) * 100;
}


function ptScanString($string) {
	global $cryptam_executable_sigs, $cryptam_plaintext_sigs, $global_engine;
	$rank = 0;
	$pt = 0;
	$hits = array();

	foreach($cryptam_plaintext_sigs as $search => $desc) {
		if (strstr($search, '?')) {
			
			preg_match("/$search/is", $string, $matches, PREG_OFFSET_CAPTURE);
			//var_dump($matches);
			if (isset($matches['0']['0']) ) {
				//echo "$desc\n";
				$l = $matches['0']['1'];
				$rank += 301;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregex', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');


			}
		} else if ($l = stripos($string, $search)) {
				//echo "$desc\n";
				$rank += 300;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptstring', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');

		}
	}
	$hits['rank'] = $rank;
	$hits['pt'] = $pt;
	return $hits;

}



//search for clear text signatures
function ptScanFile($string) {
	global $cryptam_executable_sigs, $cryptam_plaintext_sigs, $global_engine;
	$rank = 0;
	$pt = 0;
	$hits = array();

	foreach($cryptam_plaintext_sigs as $search => $desc) {
		if (strstr($search, '?')) {
			
			preg_match("/$search/is", $string, $matches, PREG_OFFSET_CAPTURE);
			//var_dump($matches);
			if (isset($matches['0']['0']) ) {
				//echo "$desc\n";
				$l = $matches['0']['1'];
				$rank += 301;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregex', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');


			}
		} else if ($l = stripos($string, $search)) {
				//echo "$desc\n";
				$rank += 300;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptstring', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');

		}
	}


	foreach($cryptam_executable_sigs as $search => $desc) {
		if (strstr($search, '?')) {
			preg_match("/$search/is", $string, $matches, PREG_OFFSET_CAPTURE);
			//var_dump($matches);
			if (isset($matches['0']['0']) ) {
				$l = $matches['0']['1'];
				//echo "$desc\n";
				$rank += 400;
				
				$pt++;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregex', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'string', 'exploit_type' => 'string',
						'hit_desc' => $desc);

			}
		} else {

			 if (($l = strpos($string, $search)) !== FALSE) {
				//echo "$desc\n";
				$rank += 400;
				$pt++;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptstring', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'string', 'exploit_type' => 'string',
						'hit_desc' => $desc);
			}

			for($i = 1; $i <= 7; $i++) {
				$rolsearch = cipherRol($search, $i);
				if ($rolsearch != $search) {
					if (($l = strpos($string, $rolsearch)) !== FALSE) {
						$rank += 400;
						$pt++;
						$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptrol', 
							'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "rol"."$i.".$desc,
 							'hit_encoding' => 'rol'.$i);
					}
				}
				$notsearch = cipherNot($search);
				if (($l = strpos($string, $notsearch))!== FALSE) {
					$rank += 400;
					$pt++;
					$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptnot', 
						'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "not.".$desc,
 						'hit_encoding' => 'not');
		
				}
			
			}

		}
	}


	if ($pt == 0) {

		//check for xor look ahead cipher
		$lookAhead = xorAheadString($string);
		foreach($cryptam_executable_sigs as $search => $desc) {
			if (!strstr($search, '?')) {
				 if (($l = strpos($lookAhead, $search))!== FALSE) {
					//echo "$desc\n";
					$rank += 400;
					$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorlaptstring', 
						'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'xorla', 'exploit_type' => 'string',
							'hit_desc' => "xorla.".$desc);
				}

			}
		}
		unset($lookAhead);
	}

	//decompress flash and scan with plaintext sigs
	if (preg_match_all("/\\x00\\x00CWS(.*)\\x00\\x00\\x00\\x00\\x00\\x00\\x00/s", $string, $match, PREG_OFFSET_CAPTURE)) {
		if (isset($match[1])) {
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					//echo $matches0[1]." CWS".$matches0[0];
					$unc = flashExplode("CWS".$matches0[0]);
					//echo $unc;
					$loc = $matches0[1];

					foreach($cryptam_plaintext_sigs as $search => $desc) {
						if (stristr($search, '?')) {
							preg_match("/$search/is", $unc, $matches, PREG_OFFSET_CAPTURE);
							//var_dump($matches);
							if (isset($matches['0']['0']) ) {
								//echo "$desc\n";
								$l = $matches['0']['1']+$loc;
								$rank += 301;

								$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregexflash', 'exploit' => "cws.".$desc,
									'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "cws.".$desc,
 											'hit_encoding' => 'string', 'flash' => base64_encode($unc), 'flash_loc' => $loc);


							}
						} else if ($l = stripos($unc, $search)) {
								//echo "$desc\n";
								$rank += 300;
								$hits[$l] = array('exploit_loc' => $l+$loc, 'searchtype' => 'ptstringflash', 'exploit' => "cws.".$desc,
									'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "cws.".$desc,
 											'hit_encoding' => 'string', 'flash' => base64_encode($unc), 'flash_loc' => $loc);

						}
					}
				}
			}
		}
	}




	$hits['rank'] = $rank;
	$hits['pt'] = $pt;
	return $hits;

}



if (!function_exists('hex2str')) {

	function hex2str($hex) {
		$hex = preg_replace("/[^A-Za-z0-9]/", '', $hex);
		$str = '';
		for($i=0;$i<strlen($hex);$i+=2) {
			$str.=chr(hexdec(substr($hex,$i,2)));
  		}
  		return $str;
	}
}


function xorString($data, $key, $zero = 0) {
	$key_len = strlen($key);
	$newdata = '';
 
	if ($key_len == 0)
		return $data;
	for ($i = 0; $i < strlen($data); $i++) {
        	$rPos = $i % $key_len;
		$r = '';
		if ($key_len == 1) {
			if ($zero == 0 || $data[$i] != "\x00")
				$r = ord($data[$i]) ^ ord($key);
			else 
				$r = ord($data[$i]);
		} else
			$r = ord($data[$i]) ^ ord($key[$rPos]);
 
		$newdata .= chr($r);
	}
 
	return $newdata;
}


function xorAheadString($data) {
	$newdata = '';
 
	for ($i = 0; $i < strlen($data)-1; $i++) {
 		$r =  ord($data[$i]) ^ ord($data[$i+1]) ;
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





function normalizeKey($key) {
	$values = hex2str($key).hex2str($key);
	$size= strlen($values) / 2;
	$high = chr(0x00);
	$highest = '';
	$highestLoc = 0;
	for ($j = 0; $j < $size; $j++) {
		for ($i = 0; $i < $size; $i++) {
			if (strlen($highest) > 0) {
				$check = substr($values,$i,strlen($highest));
				if ($highest == $check) {
					$pos = $i+strlen($highest);
					if ($values[$pos] > $high) {
						$highestLoc = $i-1;
						$high = $values[$pos];
					}
				}
			} else {
				if ($values[$i] > $high) {
					$highestLoc = $i-1;
					$high = $values[$i];

				}
			}

		}
		$highest .= $high;
		$high = chr(0x00);
		
		$search = '';
		for ($l = 0; $l < strlen($highest); $l++) {
			$search .= "\x".dechex(ord($highest[$l]));
		}

		if (preg_match_all("/$search/s", $values, $matches, PREG_OFFSET_CAPTURE)) {
			if (count($matches[0]) <= 2) {
				break;
			}
		}
	}

	$new = '';
	for($i = $highestLoc+1; $i < $highestLoc+$size+1; $i++) {
		$new .= $values[$i];
	}
	return strhex($new);
}

if (!function_exists('strhex')) {

	function strhex($string) {

		$hex = '';
		$len = strlen($string);
   
		for ($i = 0; $i < $len; $i++) {
        
			$hex .= str_pad(dechex(ord($string[$i])), 2, 0, STR_PAD_LEFT);
   
		}
       
		return $hex;
    
	}
}


function scanFile($data, $key) {
	global $cryptam_executable_sigs, $global_engine;


	$unxor = xorString($data, hex2str($key));
	$hits = array();


	if (strlen($key) == 0)
		return $hits;

	//echo "<P>Checking for xored signatures</P>\n";
	foreach ($cryptam_executable_sigs as $search => $desc) {
		if (($l = strpos($unxor, $search))!== FALSE) {

				//echo "<P>Found $desc as $l</P>\n";

				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorstring', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc, 'hit_encoding' => 'string');



		}
		for($i = 1; $i <= 7; $i++) {
			$rolsearch = cipherRol($search, $i);
			if ($rolsearch != $search) {
				if (($l = strpos($unxor, $rolsearch))!== FALSE) {
					$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorrol', 
						'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "rol"."$i.".$desc, 							'hit_encoding' => 'rol'.$i);
				}
			} //else
				//echo "<P>warn $i $search = $rolsearch</P>\n";
		}
		$notsearch = cipherNot($search);
		if (($l = strpos($unxor, $notsearch))!== FALSE) {
			$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xornot', 
				'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "not.".$desc,
				'hit_encoding' => 'not');

		} 


	}
	return $hits;

}




function scanXORByte($data) {
	global $cryptam_executable_sigs, $global_engine;

	$hits = array();

	$rxor = '';



	foreach ($cryptam_executable_sigs as $searchorig => $desc) {

		for($k = 1; $k < 256; $k++) {
			$search = xorString($searchorig, chr($k));
			$xor = sprintf("%02x", $k);


			if (($l = strpos($data, $search))!== FALSE) {
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorb', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".".$desc, 'hit_encoding' => "xor_0x".$xor);
				$rxor = $xor;
			}
			for($i = 1; $i <= 7; $i++) {
				$rolsearch = cipherRol($search, $i);
				if ($rolsearch != $search) {
					if (($l = strpos($data, $rolsearch))!== FALSE) {
						$xor = sprintf("%02x", ord(cipherRol(chr($k), $i)));	
						$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorbrol', 
							'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".rol".$i.".".$desc, 											'hit_encoding' => "xor_0x".$xor.'.rol'.$i);
						$rxor = $xor;
					}
				} 
			}
			$notsearch = cipherNot($search, $i);
			if (($l = strpos($data, $notsearch))!== FALSE) {
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorbnot', 
				'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".not".".".$desc,
 				'hit_encoding' => "xor_0x".$xor.'.not');
				$rxor = $xor;
			} 


		}


	}
	$hits['xor'] = $rxor;
	return $hits;

}




function key_align($s = "provided", $t = "true known key") {

	$shortest = get_longest_common_subsequence($t, $s);

	$l = strpos($s, $shortest[0]);
	$l2= strpos($t, $shortest[0]);

	//echo "l= $l , l2 = $l2\n";
	$start = $l2-$l;
	if ($start < 0)
		$start+=strlen($s);
	return substr($t.$t, $start, strlen($s));
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


function get_longest_common_subsequence($string_1, $string_2) {
        $string_1_length = strlen($string_1);
        $string_2_length = strlen($string_2);
        $return          = array();
 
        if ($string_1_length === 0 || $string_2_length === 0) {
                // No similarities
                return $return;
        }
 
        $longest_common_subsequence = array();
 
        // Initialize the CSL array to assume there are no similarities
        for ($i = 0; $i < $string_1_length; $i++) {
                $longest_common_subsequence[$i] = array();
                for ($j = 0; $j < $string_2_length; $j++) {
                        $longest_common_subsequence[$i][$j] = 0;
                }
        }
 
        $largest_size = 0;
 
        for ($i = 0; $i < $string_1_length; $i++) {
                for ($j = 0; $j < $string_2_length; $j++) {
                        // Check every combination of characters
                        if ($string_1[$i] === $string_2[$j]) {
                                // These are the same in both strings
                                if ($i === 0 || $j === 0) {
                                        // It's the first character, so it's clearly only 1 character long
                                        $longest_common_subsequence[$i][$j] = 1;
                                } else {
                                        // It's one character longer than the string from the previous character
                                        $longest_common_subsequence[$i][$j] = $longest_common_subsequence[$i - 1][$j - 1] + 1;
                                }
 
                                if ($longest_common_subsequence[$i][$j] > $largest_size) {
                                        // Remember this as the largest
                                        $largest_size = $longest_common_subsequence[$i][$j];
                                        // Wipe any previous results
                                        $return       = array();
                                        // And then fall through to remember this new value
                                }
 
                                if ($longest_common_subsequence[$i][$j] === $largest_size) {
                                        // Remember the largest string(s)
                                        $return[] = substr($string_1, $i - $largest_size + 1, $largest_size);
                                }
                        }
                        // Else, $CSL should be set to 0, which it was already initialized to
                }
        }
 
        // Return the list of matches
        return $return;
}


if (!function_exists('flashExplode')) {

	function flashExplode ($stream) {

		$magic = substr($stream, 0, 3);

		if ($magic == "CWS") {
			$header = substr($stream, 4, 5);
			$content = substr($stream, 10);
			$uncompressed = gzinflate($content);
			return "FWS".$header.$uncompressed;
		} else
			return $stream;
	}
}



function multiDecode($raw, $params =  array()) {
	$key = '';
	$rol = 0;
	$ror = 0;
	$tph = 0;
	$tp = 0;
	$la = 0;

	$not = 0;
	$zero = 0;
	$out = '';
	$data = $raw;

	if (isset($params['key_rol']))
		$ror = $params['key_rol'];
	if (isset($params['key']))
		$key = $params['key'];
	if (isset($params['key_tp']))
		$tp = $params['key_tp'];
	if (isset($params['key_tph']))
		$tph = $params['key_tph'];
	if (isset($params['key_not']))
		$not = $params['key_not'];
	if (isset($params['file']))
		$out = $params['out'];
	if (isset($params['key_zero']))
		$zero = $params['key_zero'];
	if (isset($params['key_la']))
		$la = $params['key_la'];




	if ($key != '') {
		//echo "using XOR key $key\n";
		$data = xorString($data, hex2str($key), $zero);
	}

	if ($rol != 0 && $rol != '') {
		//echo "using ROL $rol\n";
		$data = cipherRol($data, $rol);
	}

	if ($ror != 0  && $ror != '') {
		//echo "using ROR $ror\n";
		$data = cipherRor($data, $ror);
	}

	if ($not != 0 && $not != '') {
		//echo "using bitwise not\n";
		$data = cipherNot($data);
	}

	if ($la != 0 && $la != '') {
		//echo "using lookahead not\n";
		$data = xorAheadString($data);
	}

	if ($tp != 0  && $tp != '') {
		//echo "using transposition decoder\n";
		$data = untranspose($data);
	}

	//if ($tph != 0  && $tph != '') {
		//echo "note first 512 bytes of EXE may be transpositioned\n";
	//}

	return $data;
}



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

if (!function_exists('mtyara')) {

	function mtyara($filename, $signature_file) {
		global $global_yara_cmd;

		if (substr($global_yara_cmd, -6) == " -s -m") {
			logdebug("changed yara command to remove extra options");
			$global_yara_cmd = substr($global_yara_cmd, 0, (strlen($global_yara_cmd) - 6));

		}
		if (!is_executable($global_yara_cmd))
			echo "warning: $global_yara_cmd is not executable\n";

		exec("$global_yara_cmd ".escapeshellarg($signature_file)." ".escapeshellarg($filename).' 2>&1', $out);

		$yara_result = array();
		$current_rule = '';
		$error = '';

		foreach ($out as $line) {
			if (preg_match("/^(\w+) (.*)$/",$line, $matches)) {
				list($l, $hit, $rest) = $matches;
				$current_rule = $hit;

				if ($hit != "error" && $rest != "error")
					$yara_result[$hit] = $rest; 
			} else {
				$error .= "$line\n";
			}
		}
		if ($error != '')
			logdebug( "yara error: $error");
		return $yara_result;
	}
}

if (!function_exists('mtyaradir')) {

	function mtyaradir($filename, $signature_file) {
		global $global_yara_cmd;

		if (substr($global_yara_cmd, -6) == " -s -m") {
			logdebug("changed yara command to remove extra options");
			$global_yara_cmd = substr($global_yara_cmd, 0, (strlen($global_yara_cmd) - 6));

		}

		if (!is_executable($global_yara_cmd))
			echo "warning: $global_yara_cmd is not executable\n";

		exec("$global_yara_cmd -r ".escapeshellarg($signature_file)." ".escapeshellarg($filename).' 2>&1', $out);

		$yara_result = array();
		$current_rule = '';
		$error = '';

		foreach ($out as $line) {
			if (preg_match("/^(\w+) (.*)$/",$line, $matches)) {
				list($l, $hit, $rest) = $matches;
				$current_rule = $hit;
				$yara_result[$hit] = $rest; 
			} else {
				$error .= "$line\n";
			}
		}
	
		if ($error != '')
			logdebug( "yara error: $error");
		return $yara_result;
	}
}



if (!function_exists('mtyara2')) {

	function mtyara2($filename, $signature_file) {
		global $global_yara_cmd;

		exec("$global_yara_cmd ".escapeshellarg($signature_file)." ".escapeshellarg($filename).' 2>&1', $out);

		$yara_result = array();
		$current_rule = '';
		$error = '';

		foreach ($out as $line) {
	
			if (substr($line, 0, 2) == "0x") {
				preg_match("/^0x([\da-fA-F]+):.(\w+): (.*)$/",$line, $matches);
				if (count($matches) < 3)
					break;
				list($all,$loc,$var, $string) = $matches;
				$loc_dec = hexdec($loc);
				$yara_result[$current_rule]['hits'][$loc] = array('loc_dec' => $loc_dec, 'var' => $var, 'string' => $string);
			} else if (preg_match("/^(\w+) \[(.*)\] (.*)$/",$line, $matches)) {
		
				list($all,$rule,$meta, $file) = $matches;
				$current_rule = $rule;

				$metadata = array();
				foreach (preg_split("/,(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))/",trim($meta)) as $item) {
					if (strpos($item, "=") !== FALSE) {
						list($name,$value) = explode('=', $item);
						$metadata[$name] = trim($value, '"');
					}
				}		
				$yara_result[$current_rule] = array('metadata' => $metadata, 'filename' => $file); 
			} else
				$error .= $line;


		}

		if ($error != '' || count($yara_result) == 0) return $error;

		return $yara_result;
	}
}


if (!function_exists('yara_wrapper')) {

	function yara_wrapper($data) {
		global $global_yara_sig,$docdir;

		$tmp_file = "$docdir"."mwtcrtmyara-".uniqid();
		file_put_contents($tmp_file, $data);

		$result = mtyara($tmp_file, $global_yara_sig);
		unlink($tmp_file);
		return $result;
	}
}

if (!function_exists('yara_wrapper_file')) {
	function yara_wrapper_file($file) {
		global $global_yara_sig;

		$result = mtyara($file, $global_yara_sig);

		return $result;

	}
}


if (!function_exists('yara_wrapper_dir')) {
	function yara_wrapper_dir($dir) {
		global $global_yara_sig;

		$result = mtyaradir($dir, $global_yara_sig);

		return $result;

	}
}


function longestOne($string) {
	$longest = array('pos' => 0, 'len' => 0);
	preg_match_all('/[1]{1,}/', $string, $matches, PREG_OFFSET_CAPTURE);
	if (isset($matches[0])) {
		foreach ($matches[0] as $item) {
			if (strlen($item[0]) > $longest['len']) {
				$longest['len'] = strlen($item[0]);
				$longest['pos'] = $item[1];
			}
		}
	}
	return $longest;
}


function stripXML($xml) {
	return strip_tags($xml, '<?xml>');
}


function parseRTF($rtf) {
	$tree = '';
	$le = strlen($rtf);
	for ($i = 0; $i < $le; $i++){
		

		if ($i + 5 < $le && $rtf[$i+1] == '\\' && $rtf[$i+2] == '\'') {
			//echo "nibble $i\n";
			$i += 4;

		} elseif ($rtf[$i] == '\\') {
			//store this and next
			//advance

			//follow the white rabbit and remove control words
				$j = 0;
				for ($j = $i+1; $j < strlen($rtf); $j++){
					if (ctype_space($rtf[$j])) {
						break;
					} elseif (($rtf[$j] == '{' || $rtf[$j] == '}') && $rtf[$j-1] != '\\' ) {
						$j--;
						break;
					}
				}
				$i = $j;

					

		} elseif ($rtf[$i] == '{' ) {
			//follow the white rabbit and remove control words
			if($rtf[$i+1] == '\\') {
				$j = 0;
				for ($j = $i+2; $j < strlen($rtf); $j++){
					if (ctype_space($rtf[$j])) {
						break;
					} elseif (($rtf[$j] == '{' || $rtf[$j] == '}') && $rtf[$j-1] != '\\' ) {
						$j--;
						break;
					}
				}
				$i = $j;
			} 
		} elseif ($rtf[$i] == '}' ) {
		//do nothing

		} elseif (!ctype_graph($rtf[$i])) {
		//do nothing

		} else {
			//store this
			$tree .= $rtf[$i];

		}
	}
	return $tree;
}



?>