rule JS_content_dangerous {
    meta:
        author = "Lionel PRAT"
        description = "File content potential code javascript"
        version = "0.1"
        weight = 2
        tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
        check_level2 = "check_command_bool,check_clsid_bool,check_js_bool"
        var_match = "js_file_bool"
    strings:
        $js0 = "function " nocase
        $js1 = "return" nocase
        $js2 = "var " nocase
        $k0 = "if " nocase
        $k1 = "else " nocase
        $k2 = "do " nocase
        $k3 = "while " nocase
        $k4 = "for " nocase
        $var = /(^|\s+)var\s+\S+\s*=[^;]+;/ nocase
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s*{/ nocase
        $dang1 = "eval(" nocase
        $dang2 = "User-Agent" nocase
        $dang3 = "ActiveX" nocase
        $dang4 = "WScript" nocase
        $dang5 = "XMLHTTP" nocase
        $dang6 = "ADODB." nocase
        $obf0 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf1 = /[aeuoiy]{4,}/ nocase
		$obf2 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf3 = "eval(" nocase
		$obf4 = /(function\s+.*){3,}/ nocase // base 64
    condition:
        (2 of ($js*) and 2 of ($k*) and $func and $var) and (any of ($dang*) or 3 of ($obf*))
}
