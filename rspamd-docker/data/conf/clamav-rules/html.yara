rule html_with_script {
	meta:
		description = "HTML with script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "MITRE ATTACK"
	    tag = "attack.execution"
	    check_level2 = "check_command_bool,check_clsid_bool,check_vbscript_bool,check_js_bool"
	    var_match = "htmlscript_file_bool"
	strings:
	    $magic1 = "<html>"
            $magic2 = "</html>"
	    $script = "</script>" nocase ascii wide
	    $script1 = "<![CDATA[" nocase ascii wide
	condition:
	    ($magic1 and $magic2) and (any of ($script*))
}
