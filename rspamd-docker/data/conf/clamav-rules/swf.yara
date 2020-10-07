rule SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "no flash file in mail"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
	condition:
		$magic in (0..1024) and any of ($str*)
}

