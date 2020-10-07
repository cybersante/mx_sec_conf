rule ppaction_Office {
	meta:
		description = "Office use ppaction"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "3bff3e4fec2b6030c89e792c05f049fc"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$o1 = /action=(\"|\')ppaction\:/ nocase
	condition:
	    ( uint32(0) == 0xe011cfd0 or uint32(0) == 0x04034b50 ) and $o1
}
rule Contains_DDE_Protocol
{
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"
        
        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}
rule Encrypted_OFFICE_conf {
        meta:
			description = "OFFICE DOCUMENT encrypted conf"
            author = "Lionel PRAT"
			version = "0.1"
			weight = 7
            reference = "http://lists.clamav.net/pipermail/clamav-users/2017-November/005358.html"
			tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		strings:
			$bad0 = "<encryption" nocase
			$bad1 = "<keyData" nocase
			$bad2 = "cipherAlgorithm=" nocase
			$bad3 = "hashAlgorithm=" nocase
			$bad4 = "encryptedHmacKey=" nocase
        condition:
             ( uint32(0) == 0xe011cfd0 or uint32(0) == 0x04034b50 ) and 2 of ($bad*)
}
rule OFFICE_canary {
	meta:
		description = "Office with potential TOken canary"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://canarytokens.com/"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$canary0 = /Relationship.*\s+Target=(\")?(http|ftp)(s)?\:\/\/.*\s+TargetMode=(\")?External/ nocase ascii
		$canary1 = /INCLUDEPICTURE\s+\"(http|ftp)(s)?\:\/\// nocase ascii
	condition:
	    ( uint32(0) == 0xe011cfd0 or uint32(0) == 0x04034b50 ) and any of ($canary*)
}
rule office_document_vba
{
	meta:
		description = "Office document with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
		reference = "https://github.com/jipegit/"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
rule Office_AutoOpen_Macro {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32(0) == 0xe011cfd0 and all of ($s*) and filesize < 300000
}
rule RTF_Shellcode : maldoc
{
    meta:

        author = "RSA-IR – Jared Greenhill"
        date = "01/21/13"
        description = "identifies RTF's with potential shellcode"
            filetype = "RTF"

    strings:
        $rtfmagic={7B 5C 72 74 66}
        /* $scregex=/[39 30]{2,20}/ */
        $scregex=/(90){2,20}/

    condition:

        ($rtfmagic at 0) and ($scregex)
}
rule RTF_obfusced {
   meta:
      description = "Detects RTF obfuscated"
      author = "Lionel PRAT"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
   strings:
      $magic = { 7B 5C 72 74 }
   condition:
      $magic at 0 and uint16(4) != 0x3166
}

rule MAL_RTF_Embedded_OLE_PE {
   meta:
      description = "Detects a suspicious string often used in PE files in a hex encoded object stream"
      author = "Florian Roth"
      reference = "https://github.com/rxwx/CVE-2018-0802/blob/master/packager_exec_CVE-2018-0802.py"
      date = "2018-01-22"
   strings:
      /* Hex encoded strings */
      /* This program cannot be run in DOS mode */
      $a1 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii
      /* KERNEL32.dll */
      $a2 = "4b45524e454c33322e646c6c" ascii
      /* C:fakepath */
      $a3 = "433a5c66616b65706174685c" ascii
      /* DOS Magic Header */
      $m3 = "4d5a40000100000006000000ffff"
      $m2 = "4d5a50000200000004000f00ffff"
      $m1 = "4d5a90000300000004000000ffff"
   condition:
      uint32(0) == 0x74725c7b
      and 1 of them
}

rule rtf_with_obj {
 meta:
  author = "Lionel PRAT"
 strings:
 $objdata = "objdata" nocase
 $objemb = "objemb" nocase
 condition:
 uint32(0) == 0x74725c7b and ($objdata or $objemb)
}
