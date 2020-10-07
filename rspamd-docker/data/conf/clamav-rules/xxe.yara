rule xxe_system {
	meta:
		description = "XML with XXE SYSTEM exploit"
		author = "Lionel PRAT"
        version = "0.2"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution"
	    check_level2 = "check_command_bool,extract_xxe_bool"
	strings:
	    $xml = "<?xml" nocase
	    $soap = "<soap"
            $xxe = /<!entity [^>]+ SYSTEM / nocase ascii
	condition:
	    $xxe and ($soap or $xml)
}
