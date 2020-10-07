rule SDB_file {
	meta:
		description = "Windows application compatibility Shim DataBase (.sdb)"
		author = "Lionel PRAT"
		reference = "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1138/src"
		weight = 1
		check_level2 = "check_command_bool,check_clsid_bool"
		var_match = "sdb_file_bool"
	strings:
	    $magic = { 02 78 }
	condition:
	    uint32(8) == 0x66626473 and $magic in (0..12)
}
