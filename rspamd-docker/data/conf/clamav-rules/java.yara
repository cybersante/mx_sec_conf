rule java_jar {
    meta:
        author = "Lionel PRAT"
        description = "File java archive data (JAR)"
        version = "0.1"
        weight = 1
        check_level2 = "check_command_bool,check_java_bool"
        var_match = "java_file_bool"
        reference = "https://github.com/file/file/blob/b205e7889b9ef8d058fdc1dba2822d95d744e738/magic/Magdir/cafebabe" 
    strings:
        $magic1 = { 50 4b 03 04 }
        $magic2 = { fe ca }
        $magic3 = "META-INF/"
    condition:
        $magic1 at 0 and ($magic2 in (38..48) or $magic3 in (26..48))
}
