rule Lnk_file {
	meta:
		description = "Windows shortcut (.lnk)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		check_level2 = "check_command_bool"
		var_match = "lnk_file_bool"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
	condition:
	    $lnkmagic at 0
}
