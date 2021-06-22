<?PHP
/*
 * v2.0 May 17 2018
 * cryptam-cli.php: tyLabs.com Cryptam - general library
 * reusable analyse document functions 
  */


$docdir = "./";
$doctempdir = "/tmp/"; //temporary writeable folder


$global_zip = 'unzip -n';
$global_paranoid = 0;



function analyseDocx($path) {
	global $global_zip;
	$results = array();

	$archive_dir = $path.".zarchive".uniqid()."/";
	$unarchive_out = exec("$global_zip ".escapeshellarg($path)." -d ".escapeshellarg($archive_dir)." > /dev/null");

	if (file_exists($archive_dir)) {
		$it = new RecursiveDirectoryIterator($archive_dir);

		foreach (new RecursiveIteratorIterator($it) as $filename) {

			//echo $filename." ".$fileinfo['extension']."\n";
			chmod($filename, 0755);

			$fileinfo = pathinfo($filename);
			$newname = $path.".".uniqid()."-".$fileinfo['basename'];

			if ($fileinfo['basename'] != '.' && $fileinfo['basename'] != '..' ) {

				//if (stristr($fileinfo['basename'], "activeX" ) || $fileinfo['extension'] != 'xml') {
					//echo " running". $filename."\n";
					copy($filename,  $newname);

					//run it
					$result = array();
					if ($fileinfo['extension'] == 'xml' || $fileinfo['extension'] == 'rels') {
						$result = stringScan(file_get_contents($newname));
						if ($fileinfo['extension'] == 'xml' && $result['severity'] == 0) {
							$result = stringScan(stripXML(file_get_contents($newname)));
						}



					} else
						$result = analyseDoc($newname);

					if ($result['severity'] > 0)
						$results[$fileinfo['basename']] = $result;
					else
						unlink($newname);
				//}
			}
		
		//unlink($filename);

		}
		foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($archive_dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $path) {
			$path->isFile() ? unlink($path->getPathname()) : rmdir($path->getPathname());
		}
   		rmdir($archive_dir);
	} else {
		echo "unzip has failed\n";
	}
	
	return $results;
}


//option to plaintext scan only for open xml trusted formats that won't have embedded executables in xor

function analyseDoc($filename) {
	global $global_engine, $global_true_keys, $global_yara_sig, $global_zip, $global_paranoid;

	$md5 = md5_file($filename);
	$sha1= sha1_file($filename);
	$sha256 = hash_file("sha256", $filename);
	$fsize = filesize($filename);
		
	logDebug("$md5 start processing");

	//echo getFileMetadata($filename);

	$sampleUpdate = array('hits' => 0, 'completed' => 0, 'is_malware' => 0, 
		'summary' => '', 'severity' => 0,
		'key' => '', 'key_len' => '', 'key_hash' => '', 'key_rol' => '', 'key_not' => '',
		'key_tp' => '', 'key_tph' => '', 'key_math' => '', 'key_la' => '', 'key_special' => '',
		'key_rank' => '', 'metadata'=> getFileMetadata($filename), 'has_exe' => 0,
		'md5' => $md5, 'sha1' => $sha1, 'sha256' => $sha256, 'yara' => array());
	$data = file_get_contents($filename);


	//check for MS Office xml format:
	if (substr($data, 0, 2) == "PK") {
		logDebug("$md5 is a PK Zip");
		$xmlembedded = analyseDocx($filename);

		foreach ($xmlembedded as $fname => $xresult) {
			if ($xresult['severity'] > 0) {
				$sampleUpdate['severity'] += $xresult['severity'];
				if ($xresult['has_exe'] == 1)
					$sampleUpdate['has_exe'] = 1;
				if (isset($xresult['yara']))
					$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;
				if ($xresult['is_malware'] == 1)
					$sampleUpdate['is_malware'] = 1;
				$summaries = explode("\n", $xresult['summary']);
				$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
				foreach ($summaries as $line) {
					if ($line != '')
						$sampleUpdate['summary'] .= "$fname.$line\n";
				}
				$sampleUpdate['completed'] = 1;
			}
		}
		if (isset($sampleUpdate['severity']) && $sampleUpdate['severity'] > 0)
			return $sampleUpdate;

	}

	//check for an embedded PK Zip OpenXML doc header 504B03041400
	if (($pk = strpos($data,"\x50\x4B\x03\x04\x14\x00")) > 0) {
		file_put_contents($filename.".openxml", substr($data, $pk));

		logDebug("has pk inside $pk");
		$xmlembedded = analyseDocx($filename.".openxml");

		foreach ($xmlembedded as $fname => $xresult) {
			if ($xresult['severity'] > 0) {
				$sampleUpdate['severity'] += $xresult['severity'];
				if ($xresult['has_exe'] == 1)
					$sampleUpdate['has_exe'] = 1;
				if (isset($xresult['yara']))
					$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;
				if ($xresult['is_malware'] == 1)
					$sampleUpdate['is_malware'] = 1;
				$summaries = explode("\n", $xresult['summary']);
				$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
				foreach ($summaries as $line) {
					if ($line != '')
						$sampleUpdate['summary'] .= "$fname.$line\n";
				}
				//$sampleUpdate['completed'] = 1;
			}
		}

		//var_dump($sampleUpdate);
	}


	$dataa = $data;
	$local = 0;
	//check for an embedded zlib doc header 0000789c
	while (($pk = strpos($dataa,"\x00\x00\x78\x9c")) > 0) {
		file_put_contents($filename.".openxml", substr($dataa, $pk));
		$local += $pk;
		logDebug("has pk inside $pk");
		//$dec = @gzinflate(substr($dataa, $pk+12));
		$dec = '';

		for($i = 4; $i <= 6; $i+=2) {
			$dec = @gzinflate(substr($dataa, $pk+$i));
			if (strlen($dec) > 0) {
				break;
			}
		}

		if (strlen($dec) > 0) {
			$l = $local;
			$datastored = array();
			file_put_contents($filename."-datastore-".$l, $dec);
			$dresult = analyseDoc($filename."-datastore-".$l);

			if ($dresult['severity'] > 0)
				$datastored["datastore-".$l] = $dresult;
			else
				unlink($filename."-datastore-".$l);
			
					
			
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '') {
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
						}
					}
					$sampleUpdate['completed'] = 1;
				}
			}
		}

		

		$dataa = substr($dataa, $pk+4);
	}
	unset($dataa);






	$dataa = $data;
	$local = 0;
	//check for an embedded ExOleObjStgCompressedAtom doc header 10001110
	while (($pk = strpos($dataa,"\x10\x00\x11\x10")) > 0) {
		file_put_contents($filename.".openxml", substr($dataa, $pk));
		$local += $pk;
		logDebug("has pk inside $pk");
		//$dec = @gzinflate(substr($dataa, $pk+12));
		$dec = '';

		for($i = 10; $i <= 16; $i+=2) {
			$dec = @gzinflate(substr($dataa, $pk+$i));
			if (strlen($dec) > 0) {
				break;
			}
		}

		if (strlen($dec) > 0) {
			$l = $local;
			$datastored = array();
			file_put_contents($filename."-datastore-".$l, $dec);
			$dresult = analyseDoc($filename."-datastore-".$l);

			if ($dresult['severity'] > 0)
				$datastored["datastore-".$l] = $dresult;
			else
				unlink($filename."-datastore-".$l);
			
					
			
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '') {
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
						}
					}
					$sampleUpdate['completed'] = 1;
				}
			}
		}

		

		$dataa = substr($dataa, $pk+4);
	}
	unset($dataa);


	//check for datastore in RTF
	if (stristr(substr($data, 0, 256),'\rt')) {


		$d = parseRTF($data);
		preg_match_all("/([a-zA-Z0-9\x0a\x0d\x09]*)/s", $d, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[1][0])) {
			$datastored = array();
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					$len = strlen($matches0[0]);
					if ($len > 256) {
						file_put_contents($filename."-datastore-".$l, hex2str($matches0[0]));
						//echo hex2str($matches0[0]);
						$dresult = analyseDoc($filename."-datastore-".$l);

						if ($dresult['severity'] > 0)
							$datastored["datastore-".$l] = $dresult;
						else {
							unlink($filename."-datastore-".$l);
							file_put_contents($filename."-datastore-".$l, hex2str("0".$matches0[0]));
							//echo hex2str($matches0[0]);
							$dresult = analyseDoc($filename."-datastore-".$l);

							if ($dresult['severity'] > 0)
								$datastored["datastore-".$l] = $dresult;
							else {
								unlink($filename."-datastore-".$l);

							}

						}
					}
					
				}
			}
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '') {
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
						}
					}
					$sampleUpdate['completed'] = 1;
				}
			}
			//store datastore xor information

		}

	}



	//check for datastore in Postscript
	if (stristr(substr($data, 0, 4),'%!PS')) {
		preg_match_all("/([a-zA-Z0-9\x0a\x0d\x20\x09]*)/s", $d, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[1][0])) {
			$datastored = array();
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					$len = strlen($matches0[0]);
					if ($len > 1024) {
						file_put_contents($filename."-datastore-".$l, hex2str($matches0[0]));
						//echo hex2str($matches0[0]);
						$dresult = analyseDoc($filename."-datastore-".$l);

						if ($dresult['severity'] > 0)
							$datastored["datastore-".$l] = $dresult;
						else
							unlink($filename."-datastore-".$l);
					}
					
				}
			}
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '') {
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
						}
					}
					$sampleUpdate['completed'] = 1;
				}
			}
			//store datastore xor information

		}
	}

	//check for data in mime mso xml
	if (stristr(substr($data, 0, 256),'xml') || stristr(substr($data, 0, 256),'MIME-Version') ) {						preg_match_all("/([a-zA-Z0-9\/+=\x0a\x0d]{1024,})/s", $data, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[1][0])) {
			$datastored = array();
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					$d64 = "";
					if (substr($matches0[0], 0, 3) == "mso")
						$d64 = base64_decode(substr($matches0[0], 4), false);
					else
						$d64 = base64_decode($matches0[0], false);


					$len0 = strlen($d64);

					if ($len0 > 0) {

						if (stristr(substr($d64, 0, 10), 'ActiveMime' )) {

							$s64 = $d64;
							$d64 = @gzuncompress(substr($s64, 50) );
						
							$len = strlen($d64);

							if ($len == 0) {
								
								for ($i=0;$i < strlen($s64); $i++) {
									$d64 = @gzuncompress(substr($s64, $i));
									$len = strlen($d64);
									if ($len > 0) break;
								}

							}
						}
					}

					$len = strlen($d64);
					if ($len > 1024) {
						file_put_contents($filename."-datastore-".$l, $d64);

						$dresult = analyseDoc($filename."-datastore-".$l);

						if ($dresult['severity'] > 0)
							$datastored["datastore-".$l] = $dresult;
						else
							unlink($filename."-datastore-".$l);
					}
					
				}
			}
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '') {
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
						}
					}
					$sampleUpdate['completed'] = 1;
				}
			}
			//store datastore xor information

		}
	}


	$result = cryptoStat($data);
	$exploits = array();
	$hits = array();
	if (isset($result['exploits'])) {
		$exploits = $result['exploits'];
		unset($result['exploits']);
	}

	foreach ($sampleUpdate as $key => $value) {
		if ($value != "0" && $value != '')
			if (!isset($result[$key]) || $result[$key] == 0 || $result[$key] == 0)
				unset($result[$key]);
	}

	$result = array_merge($sampleUpdate,$result);

	$summary = $result['summary'];
	$severity = $result['severity'];

	$rol = 0;
	$not = 0;
	$la = 0;
	$tp = 0;
	$tph = 0;
	$math = 0;
	$has_exe = $result['has_exe'];


	foreach ($exploits as $l => $hit) {
		if (isset($hit['exploit']) && $hit['exploit'] != '') {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			if (preg_match("/exploit\./", $hit['hit_desc'], $match))
				$severity += 20;
			else
				$severity += 2;
			
		} else {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}

	}

	if ( $has_exe == 1) { //plaintext
		$result['key'] = '';
		$result['key_len'] = 0;
		$result['key_occ'] = 0;
		$result['key_hash'] = '';
		$result['key_rank'] = 0;
		$result['key_entropy'] = '';


	} else if ($result['key'] == "00") {
		//echo "<P>key 00 recheck</P>\n";
		$xorexp = scanXORByte($data);
		$xor = $xorexp['xor'];
		//var_dump($xorexp);
		unset($xorexp['xor']);
		if ($xor != '') {
			$result['key'] = $xor;
			$result['key_len'] = 1;
			$result['key_occ'] = 0;
			$result['key_entropy'] = 100.0;
			$result['key_zero'] = 1;

			foreach ($xorexp as $l => $hit) {
				$hit['parent_md5'] = $md5;
				$hit['parent_sha256'] = $sha256;
				$hits[$hit['exploit_loc']] =  $hit;
				$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
				$severity += 10;

				if (preg_match("/\.rol(\d+)/", $hit['hit_desc'], $match))
					$rol = $match[1];
				if (preg_match("/\.not/", $hit['hit_desc'], $match))
					$not = 1;
				if (preg_match("/\.xorla/", $hit['hit_desc'], $match))
					$la = 1;

				if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
					if (preg_match("/This program/", $hit['hit_desc'], $match))
						$tph = 1;
					else
						$tp = 1;
				}

				$has_exe = 1;
			}
		} else {
			$result['key'] = '';
			$result['key_len'] = 0;
			$result['key_occ'] = 0;
			$result['key_entropy'] = '';
			if (count($hits) == 0)
				$result['is_malware'] = 0;
			
		}


	} else if (isset($result['key_len'])  && $result['key_len'] > 0) {
		$malware = scanFile($data, $result['key']);

		if (count($malware) <= 1) {
			
			foreach ($global_true_keys as $tkey) {
				$tkey_count = substr_count($data,hex2bin($tkey));
				if ($tkey_count > 1) {
					$kl = strlen($tkey) / 2;
					$tkey_try = substr($tkey.$tkey,($kl-strpos($data,hex2bin($tkey)) % $kl)*2, $kl*2);
					$m2 = scanFile($data, $tkey_try);
					if (count($m2) > 1) {
						$result['key'] = $tkey_try;
						$result['key_len'] = strlen($tkey_try)/2;
						$malware = $m2; //import
						break;
					}



				}
				
			}
		}


		foreach ($malware as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


	}

	if ($result['key_len'] == 1024 && $has_exe != 1) {
		$xorexp = scanXORByte($data);
		$xor = $xorexp['xor'];
		//var_dump($xorexp);
		unset($xorexp['xor']);
		if ($xor != '') {
			$result['key'] = $xor;
			$result['key_len'] = 1;
			$result['key_occ'] = 0;
			$result['key_entropy'] = 100.0;
			$result['key_zero'] = 1;

			foreach ($xorexp as $l => $hit) {
				$hit['parent_md5'] = $md5;
				$hit['parent_sha256'] = $sha256;
				$hits[$hit['exploit_loc']] =  $hit;
				$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
				$severity += 10;

				if (preg_match("/\.rol(\d+)/", $hit['hit_desc'], $match))
					$rol = $match[1];
				if (preg_match("/\.not/", $hit['hit_desc'], $match))
					$not = 1;
				if (preg_match("/\.xorla/", $hit['hit_desc'], $match))
					$la = 1;
	
				if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
					if (preg_match("/This program/", $hit['hit_desc'], $match))
						$tph = 1;
					else
						$tp = 1;
				}

				$has_exe = 1;
			}
		} else {
			$result['key'] = '';
			$result['key_hash'] = '';
			$result['key_len'] = 0;
			$result['key_rank'] = 0;
			$result['key_occ'] = 0;
			$result['key_entropy'] = '';
			if (count($hits) == 0 && $severity < 2) { //Mar 5 2015
				$result['is_malware'] = 0;

			}
			
		}

	}


	if ($result['is_malware'] == 1 && $severity == 0) 
		$severity = 1;

	$result['has_exe'] = $has_exe;



	//check near the end of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks']) && $fsize > 20000 && $global_paranoid == 1) {
		//echo "trigger special case for dropped document uses a different key then exe, inverse3\n";
		$longest = longestOne($result['key_blocks']);
		//var_dump($longest);
		//echo "do from ".(($longest['pos']+7)*1024)." for ".(($longest['len']-7)*1024)."\n";
		
		$subres = cryptoStat(substr($data, (($longest['pos']+7)*1024), (($longest['len']-7)*1024)   ));		
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}







	//start start of entropy area
	if ($result['has_exe'] == 0 && isset($result['key_blocks'])&& $fsize > 20000 && $global_paranoid == 1) {
		//echo "trigger special case for dropped document uses a different key then exe\n";
		//echo $result['key_blocks']."\n";
		$check = strpos($result['key_blocks'],'11111111111');
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format(($checkFile - $check) * 0.25 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "looking at ".($check*1024)." bytes+$magicSize\n";
		$subres = cryptoStat(substr($data, $check*1024, $magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}


	//check end of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks']) && $fsize > 20000 && $global_paranoid == 1) {
		//echo "trigger special case for dropped document uses a different key then exe, inverse\n";
		//echo $result['key_blocks']."\n";
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format($checkFile * 0.14 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "-$magicSize\n";
		$subres = cryptoStat(substr($data, -$magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}


	//check middle of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks'])&& $fsize > 20000 && $global_paranoid == 1) {
		//echo "trigger special case for dropped document uses a different key then exe, middle\n";
		//echo $result['key_blocks']."\n";
		$checkFile = number_format(strlen($result['key_blocks']) / 2 * 1024, 0, '.', ''); ;
		$magicSize = $checkFile / 2;
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "$checkFile -$magicSize\n";
		$subres = cryptoStat(substr($data, $checkFile-$magicSize, $magicSize*2));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}

	//check near the end of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks'])&& $fsize > 20000 && $global_paranoid == 1) {
		//echo "trigger special case for dropped document uses a different key then exe, inverse3\n";
		//echo $result['key_blocks']."\n";
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format($checkFile * 0.14 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "-$magicSize\n";
		//echo (-$magicSize*3)." $magicSize\n";
		$subres = cryptoStat(substr($data, -$magicSize*3, $magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}


	$result['completed'] = 1;
	$result['summary'] = $summary;
	$result['severity'] = $severity;
	$result['key_rol'] = $rol;
	$result['key_not'] = $not;
	$result['key_tp'] = $tp;
	$result['key_la'] = $la;
	$result['key_tph'] = $tph;
	$result['key_math'] = $math;
	$result['has_exe'] = $has_exe;
	$result['hits'] = $hits;

	//yara original file
	if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
		//check if file is pk openxml
		if (substr($data, 0, 2) == "PK") {
			$path = $filename;
			$archive_dir = $path.".zarchive".uniqid()."/";
			$unarchive_out = exec("$global_zip ".escapeshellarg($path)." -d ".escapeshellarg($archive_dir)." > /dev/null");	
			
			if (file_exists($archive_dir)) {
				//yara in unzipped files
				$yhits = yara_wrapper_dir($archive_dir);
				
				if (is_array($yhits)) {
					foreach ($yhits as $k => $v) {
						array_push($result['yara'], $k);
					}
				}

				foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($archive_dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $path) {
					$path->isFile() ? unlink($path->getPathname()) : rmdir($path->getPathname());
				}
   				rmdir($archive_dir);
			} else {
				echo "unzip failed\n";
			}

		}



		$yhits = yara_wrapper_file($filename);
		foreach ($yhits as $k => $v) {
			array_push($result['yara'], $k);
		}
	}

	//extract embedded files
	if ($result['has_exe'] > 0) {
		$decoded = multiDecode($data, $result);
		if ($decoded != $data)
			$files = dump_pe($decoded, $filename, $tph, "datastore");
		else
			$files = dump_pe($decoded, $filename, $tph);

		foreach ($files as $loc => $filemeta) {
			$result['summary'] .= "dropped.file ".$filemeta['ext']." ".$filemeta['md5']." / ".$filemeta['len']." bytes / @ ".$loc."\n";

			//yara dropped files
			if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
				$yhits = yara_wrapper_file($filemeta['filename']);
				foreach ($yhits as $k => $v) {
					array_push($result['yara'], $k);
				}
			}


		}


		//yara xored section
		if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
			$yhits = yara_wrapper($decoded);
			foreach ($yhits as $k => $v) {
				array_push($result['yara'], $k);
			}
		}

		if ($decoded != $data)
			file_put_contents($filename.".decoded", $decoded);

	}

	$result['yara'] = array_unique($result['yara']);

	return $result;
}



?>