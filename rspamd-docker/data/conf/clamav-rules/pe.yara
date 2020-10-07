rule pe_sig
{
    meta:
        description = "PE interdit dans un courriel"
        author = "Lionel PRAT"
    strings:
            $magic = { 4D 5A }
        condition:
            $magic at 0
}

