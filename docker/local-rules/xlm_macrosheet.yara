rule XLM_Hidden_Macrosheet : maldoc heuristic suspicious {
    meta:
        description = "Hidden Excel-4.0 macrosheet detected"
        score = 60
    strings:
        $marker = "XLM-HIDDEN-MACROSHEET"
        $vh = "veryHidden"
        $h  = "hidden"
    condition:
        $marker and ($vh or $h)
}

// XLM-DANGEROUS-FUNC <FN> markers are emitted by the XLM constant-fold
// (internal/extract/xlm_fold.go emitDangerousMarkers) when a folded Excel-4.0
// formula calls a code-execution / file-dropping function. The marker prefix is
// emitted ONLY by yarad, so matching the literal is zero-FP by construction.
// EXEC/CALL/REGISTER are the Excel-4.0 dropper class (run a command, call an
// arbitrary DLL export, register a foreign function); FOPEN/FWRITE/HALT are the
// supporting file-drop + anti-analysis primitives.
rule XLM_Dangerous_Function : maldoc heuristic suspicious {
    meta:
        description = "Excel-4.0 macro calls a code-execution/file-drop function (EXEC/CALL/REGISTER/FOPEN/FWRITE/HALT)"
        score = 70
    strings:
        $exec     = "XLM-DANGEROUS-FUNC EXEC"
        $call     = "XLM-DANGEROUS-FUNC CALL"
        $register = "XLM-DANGEROUS-FUNC REGISTER"
        $fopen    = "XLM-DANGEROUS-FUNC FOPEN"
        $fwrite   = "XLM-DANGEROUS-FUNC FWRITE"
        $halt     = "XLM-DANGEROUS-FUNC HALT"
    condition:
        any of them
}

// A dangerous XLM function inside a HIDDEN/veryHidden macrosheet is the canonical
// Excel-4.0 dropper (hide the sheet from the user, run code on open). Stack the
// two markers for a higher score than either alone.
rule XLM_Hidden_Dangerous_Dropper : maldoc heuristic suspicious {
    meta:
        description = "Hidden Excel-4.0 macrosheet calling a code-execution/file-drop function (dropper)"
        score = 90
    strings:
        $hidden    = "XLM-HIDDEN-MACROSHEET"
        $danger    = "XLM-DANGEROUS-FUNC "
    condition:
        $hidden and $danger
}
