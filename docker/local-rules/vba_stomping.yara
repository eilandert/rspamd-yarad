rule VBA_Stomped
{
    meta:
        description = "VBA stomping: p-code present but decompressed source missing/trivial"
        score       = 60
        author      = "mailstrix"

    strings:
        $marker = "VBA-STOMPED "

    condition:
        $marker
}
