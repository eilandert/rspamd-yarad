/*
  VBS sibling-EXE hidden launcher.

  A tiny VBScript dropper stub that locates its own directory, then runs a
  sibling .exe in that directory with a hidden window and without waiting:

      Set sh  = CreateObject("Wscript.Shell")
      Set fso = CreateObject("Scripting.FileSystemObject")
      dir = fso.GetParentFolderName(WScript.ScriptFullName)
      sh.CurrentDirectory = dir
      sh.Run Chr(34) & dir & "\<random>.exe" & Chr(34) & " " & ..., 0, False

  The malware ships as <random>.vbs alongside <random>.exe inside one archive;
  the VBS is the autorun face that launches the real payload hidden. Variable
  and file names are randomised per sample (e.g. f5952b16…), so the rule keys
  ONLY on the stable mechanic literals, never on names.

  FP-safety: a legit "launch a sibling exe hidden" wrapper exists on disk, but
  in the MAIL-ATTACHMENT vector (mailstrix's domain) a standalone <4 KB VBS that
  self-locates via GetParentFolderName(ScriptFullName), sets CurrentDirectory
  and Run()s a sibling .exe with window-style 0 / bWaitOnReturn False has no
  benign analogue. The conjunction is 7-way AND under a tiny-file gate, so an
  incidental match on a large legitimate admin script cannot occur.

  Reference: MITRE ATT&CK T1059.005 (VBScript), T1564.003 (Hidden Window),
             T1204.002 (Malicious File).
*/

rule VBS_Sibling_Exe_Hidden_Launcher : vbs dropper launcher heuristic malware
{
    meta:
        author      = "mailstrix"
        description = "Tiny VBS that self-locates and runs a sibling .exe hidden/async (autorun dropper face)"
        reference   = "https://attack.mitre.org/techniques/T1564/003/"
        sample      = "f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92"
        score       = "70"
    strings:
        $shell  = "Wscript.Shell" nocase
        $fso    = "FileSystemObject" nocase
        $gpf    = "GetParentFolderName" nocase
        $sfn    = "ScriptFullName" nocase
        $run    = ".Run" nocase
        $exe    = ".exe" nocase
        // window-style 0 (hidden) + bWaitOnReturn False (async), spacing-tolerant.
        $hidden = /,\s*0\s*,\s*False/ nocase
    condition:
        filesize < 4096 and all of them
}
