rule scf_file {
	meta:
		description = "File Windows Explorer Command file [SCF]"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
	    check_level2 = "check_command_bool"
	    reference = "https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/"
	strings:
	    $scf0 = "[Shell]" nocase
	    $scf1 = "[Taskbar]" nocase
	    $scf3 = /Command\s*=/ nocase
	    $scf4 = /IconFile\s*=/ nocase
	condition:
	    3 of ($scf*)
}
