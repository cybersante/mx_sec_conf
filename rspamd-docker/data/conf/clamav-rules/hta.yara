rule hta_file {
	meta:
		description = "HTA file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
	    check_level2 = "check_command_bool"
	strings:
	    $hta0 = "<hta:application" nocase	    
	condition:
	    all of ($hta*)
}
