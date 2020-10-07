rule Shortcut_url {
	meta:
		description = "Shortcut Internet (.url)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
		var_match = "url_file_bool"
	strings:
	    $Shortcut_url = "[InternetShortcut]" nocase
	    $uri0 = "URL=" nocase
	    $uri1 = "://" nocase
	    
	condition:
	    $Shortcut_url and all of ($uri*)
}
