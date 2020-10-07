rule CHM_file {
	meta:
		description = "MS Windows HtmlHelp Data (.chm)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "chm_file_bool"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
	condition:
	    $chmmagic at 0
}
