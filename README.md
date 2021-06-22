# Cryptam Document Command Line Scanner

The Cryptam command line scanner is a compact PHP library to analyze documents for embedded executables, to scan for known exploits and identify suspicious elements of new threats. Embedded executables and dropped clean documents are automatically extracted.
Document formats commonly used and supported are MS Office .doc/.ppt/.xls, PDF, RTF and Open XML formats such as .docx/pptx/xlsx. Both Windows and Mac OS X executables are detected and extracted.

Cryptam is designed to detect new and emerging threats that use document formats to deliver malware, in conjunction with your enterprise antivirus and other systems, cryptam can supplement threat detection as well as assist with malware analysis by facilitating the extraction of encrypted embedded executables from documents.

## Cryptanalysis

The cryptam system attempts to reconstruct the key used to encrypt a potential embedded executable, XOR key lengths from 1-8, 16, 32, 64, 128, 256, 512, and 1024 bytes are supported, as well as any combination of those with bitwise not, and bitwise ROL shifting 1-7 which is equivalent to ROR 1-7. Plaintext and signatures for known exploits are also checked.

## Requirements

PHP 5 or greater, tested up to 7.0. PHP 5 requires modules php5-zip, php5-hash and php5-ctype
512MB RAM, 1GB Recommended

## Recommended

For safe handling of MS Windows based exploits, Linux or Mac OSX is recommended.
Yara - malware classification - http://plusvic.github.io/yara/

 
## Package Contents

cryptam-lib.php: Cryptam engine
cryptam-sig.php: detection signatures
cryptam.php: command line script
cryptam_unxor.php: standalone script to unxor or unrol a document
cryptam_multi.php: standalone script to unxor or unrol a document and extract embedded files

## Installation

Copy the PHP files to an accessible directory. It is not necessary to make the files executable.

## Running cryptam on the command line

Use the cryptam.php to specify a document file or directory of files to process:
php cryptam.php file_to_process
Command line options:
php cryptam.php <-y yara include> file_to_process
-y option to specify a Yara signature include file.

php cryptam.php file_to_process <has_exe>
Returns whether an embedded EXE is confirmed

php cryptam.php file_to_process <is_malware>
Returns binary result of scan 0 for clean 1 for malware

php cryptam.php file_to_process <summary>
Returns a textual reporting of all executable traits detected

php cryptam.php file_to_process <severity>
Returns a weighted severity of detected entities >10 is considered malware.

php cryptam.php file_to_process <key>
Returns the XOR key needed to decrypt the embedded executable.

php cryptam.php file_to_process <key_rol>
Returns the ROL key needed to decrypt the embedded executable.

php cryptam.php file_to_process <key> <key_rol>
Train multiple queries together to create your own custom output.

php cryptam.php file_to_process <key_len>
Returns the XOR key length in bytes.
php cryptam.php file_to_process <key_occ>
Returns the number of occurrences of the key in the document.

php cryptam.php file_to_process <key_hash>
Returns a md5 hash of the key reordered by weight.

*Brackets should be omitted in the actual command line option.

## Advanced Options

The following PHP variables in cryptam.php correspond to the following advanced capabilities:
$global_yara_cmd=/path/to/yara;  Yara executable.

$global_yara_sig=/path/to/yarainclude.rar;  Yara include file with signatures to scan for.

Extracting Executables
Use the supplied cryptam_unxor.php script to provide the xor key and rol shift to decrypt the embedded executables or dropped documents.

php cryptam_unxor.php file_to_process <-xor key_in_hex> <-rol 1-7> <-out output_filename>
