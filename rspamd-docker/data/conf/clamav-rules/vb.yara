rule File_contains_VB {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Suspect vbscript file embed from another File (PARENT)"
        check_level2 = "check_vbscript_bool,check_command_bool,check_clsid_bool,check_winapi_bool,check_registry_bool"
	strings:
		$vb0 = /(^|\s+|\n)sub\s+[^\(]+\(.*\)/ nocase
		$vb1 = /(^|\s+|\n)set\s+[^ ]+\s*\=\s*[^\(]+\(/ nocase
		$vb2 = /(^|\s+|\n)end\s+sub(\s+|\n|$)/ nocase
                $scriptvb0 = "CreateObject(" nocase
                $scriptvb1 = "</script>" nocase
		$obf0 = "Replace" nocase
		$obf1 = "split" nocase
		$obf2 = "Xor" nocase
		$obf3 = "Mod" nocase
		$obf4 = "chr(" nocase
		$obf5 = "mid(" nocase
		$obf6 = "asc(" nocase
		$obf7 = "KeyString(" nocase
		$obf8 = /([^ ]+\^[^ ]+){2,}/ nocase
		$obf9 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf10 = /[aeuoiy]{4,}/ nocase
		$obf11 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf12 = "ChrW(" nocase
		$obf13 = "ChrB(" nocase
		$obf14 = "abs(" nocase
		$obf15 = "eval(" nocase
		$obf16 = "join(" nocase
		$elem0 = ".Run" nocase
		$elem1 = ".ShellExecute" nocase
		$elem2 = "Shell.Application" nocase
		$elem3 = ".Exec" nocase
		$elem4 = "wscript.shell" nocase
		$elem5 = "Execute " nocase
		$elem6 = ".AppActivate" nocase
		$elem7 = "Wscript.Application" nocase
		$elem8 = ".RegDelete" nocase
		$elem9 = ".RegWrite" nocase
		$elem10 = ".RegRead" nocase
		$elem11 = ".CreateShortcut" nocase
		$elem12 = ".SendKeys" nocase
		$elem13 = ".servicest" nocase
		$elem14 = ".ShutdownWindow" nocase
		$elem15 = ".Network" nocase
		$elem16 = ".EnumNetworkDrives" nocase
		$elem17 = ".MapNetworkDrive" nocase
		$elem18 = ".RemoveNetworkDrive" nocase
		$elem19 = "FileSystemObject" nocase
		$elem20 = ".CopyFile" nocase
		$elem21 = ".CopyFolder" nocase
		$elem22 = ".MoveFile" nocase
		$elem23 = ".MoveFolder" nocase
		$elem24 = ".CreateFolder" nocase
		$elem25 = ".CreateTextFile" nocase
		$elem26 = ".DriveExists" nocase
		$elem27 = ".FileExists" nocase
		$elem28 = ".FolderExists" nocase
		$elem29 = ".OpenTextFile" nocase
		$elem30 = "eval(" nocase
		$elem31 = "\\root\\cimv2" nocase
		$elem32 = "Winmgmts:" nocase
		$elem33 = "WbemScripting.SWbemLocator" nocase
	condition:
		any of ($vb*) or all of ($scriptvb*) and (3 of ($obf*) or any of ($elem*))
}

rule vbscript {
	meta:
		description = "Potential vbscript file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		check_level2 = "check_vbscript_bool,check_command_bool,check_clsid_bool,check_winapi_bool,check_registry_bool"
		var_match = "vb_file_bool"
	strings:
		$vb0 = /(^|\s+|\n)sub\s+[^\(]+\(.*\)/ nocase
		$vb1 = /(^|\s+|\n)set\s+[^ ]+\s*\=\s*[^\(]+\(/ nocase
		$vb2 = /(^|\s+|\n)end\s+sub(\s+|\n|$)/ nocase
		$obf0 = "Replace" nocase
		$obf1 = "split" nocase
		$obf2 = "Xor" nocase
		$obf3 = "Mod" nocase
		$obf4 = "chr(" nocase
		$obf5 = "mid(" nocase
		$obf6 = "asc(" nocase
		$obf7 = "KeyString(" nocase
		$obf8 = /([^ ]+\^[^ ]+){2,}/ nocase
		$obf9 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf10 = /[aeuoiy]{4,}/ nocase
		$obf11 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf12 = "ChrW(" nocase
		$obf13 = "ChrB(" nocase
		$obf14 = "abs(" nocase
		$obf15 = "eval(" nocase
		$obf16 = "join(" nocase
		$elem0 = ".Run" nocase
		$elem1 = ".ShellExecute" nocase
		$elem2 = "Shell.Application" nocase
		$elem3 = ".Exec" nocase
		$elem4 = "wscript.shell" nocase
		$elem5 = "Execute " nocase
		$elem6 = ".AppActivate" nocase
		$elem7 = "Wscript.Application" nocase
		$elem8 = ".RegDelete" nocase
		$elem9 = ".RegWrite" nocase
		$elem10 = ".RegRead" nocase
		$elem11 = ".CreateShortcut" nocase
		$elem12 = ".SendKeys" nocase
		$elem13 = ".servicest" nocase
		$elem14 = ".ShutdownWindow" nocase
		$elem15 = ".Network" nocase
		$elem16 = ".EnumNetworkDrives" nocase
		$elem17 = ".MapNetworkDrive" nocase
		$elem18 = ".RemoveNetworkDrive" nocase
		$elem19 = "FileSystemObject" nocase
		$elem20 = ".CopyFile" nocase
		$elem21 = ".CopyFolder" nocase
		$elem22 = ".MoveFile" nocase
		$elem23 = ".MoveFolder" nocase
		$elem24 = ".CreateFolder" nocase
		$elem25 = ".CreateTextFile" nocase
		$elem26 = ".DriveExists" nocase
		$elem27 = ".FileExists" nocase
		$elem28 = ".FolderExists" nocase
		$elem29 = ".OpenTextFile" nocase
		$elem30 = "eval(" nocase
		$elem31 = "\\root\\cimv2" nocase
		$elem32 = "Winmgmts:" nocase
		$elem33 = "WbemScripting.SWbemLocator" nocase
	condition:
	    any of ($vb*) and (3 of ($obf*) or any of ($elem*))
}
