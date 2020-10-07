rule PDF_fileexport {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "PDF fonction export file (check file for found name)"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
		$export = "exportDataObject" nocase wide ascii
		$cname = "cname" nocase wide ascii
	condition:
		uint32(0) == 0x46445025 and $export and $cname
}
rule URI_on_OPENACTION_in_PDF {
   meta:
      description = "Detects Potential URI on OPENACTION in PDF"
      author = "Lionel PRAT"
      reference = "TokenCanary.pdf"
      version = "0.1"
      weight = 2
      var_match = "pdf_uri_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
   strings:
      $a = /\/S\s*\/URI\s*\/URI\s*\(/
      $b = /\/OpenAction/
   condition:
      uint32(0) == 0x46445025 and $a and $b
}
rule XFA_withJS_in_PDF {
   meta:
      description = "Detects Potential XFA with JS in PDF"
      author = "Lionel PRAT"
      reference = "EK Blackhole PDF exploit"
      version = "0.1"
      weight = 4
      var_match = "pdf_xfajs_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_command_bool"
   strings:
      $a = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
      $b = "x-javascript" nocase
   condition:
      uint32(0) == 0x46445025 and $a and $b
}
rule invalide_structure_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "Invalide structure PDF"
		weight = 5
		var_match = "pdf_invalid_struct_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}
rule suspicious_js_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion) - modified by Lionel PRAT"
		version = "0.1"
		description = "Suspicious JS in PDF metadata"
		weight = 5
		check_level2 = "check_js_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction|\/AA/
		$attrib1 = /\/JavaScript |\/JS /
      
		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		$js3 = /(^|\n)[a-zA-Z_$][0-9a-zA-Z_$]{0,100}=[^;]{200,}/
		
	condition:
		$magic in (0..1024) and (all of ($attrib*)) and 2 of ($js*)
}

rule EmbeddedFiles_PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
		$embed = /\/EmbeddedFiles/

        condition:
                $magic at 0 and $embed
}

rule encrypted_PDF
{
	meta:
		author = "Lionel PRAT"
        description = "Detect encrypted PDF"		
        strings:
		$encrypt = /\/Encrypt /
        condition:
                uint32(0) == 0x46445025 and $encrypt
}
