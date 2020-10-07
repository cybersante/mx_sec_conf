rule Otf_file {
	meta:
		description = "OpenType font data (.otf)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "otf_file_bool"
	strings:
	    $lnkmagic = { 4f 54 54 4f }
	condition:
	    $lnkmagic at 0
}
