/*
  OLE2 SummaryInformation typed-metadata markers.

  yarad's extract.oleSummaryMetaMarkers parses the SummaryInformation property
  set (MS-OLEPS) and emits typed maldoc-metadata markers into a single combined
  "OLE-META\n<marker>\n<marker>..." buffer routed to the out-of-band Markers
  channel. Every literal below is emitted ONLY by yarad -> matching is zero-FP by
  construction; the heuristics mirror oletools' meta checks.

  - OLE-META-TEMPLATE-INJECTION : Template property is a remote http(s)/UNC path
    = remote-template injection (MITRE T1221).
  - OLE-META-APPNAME-EQUATION   : AppName contains "Equation" = EQNEDT32 vector
    (CVE-2017-11882 / CVE-2018-0802).
  - OLE-META-REVISION-ZERO + OLE-META-EDITTIME-ZERO : RevNumber in {0,1} AND total
    EditTime == 0 = a freshly-minted / VBA-stomped document never interactively
    edited. Weak on their own -> required CO-LOCATED (both in one buffer) for the
    stacking rule below.

  Reference: https://learn.microsoft.com/openspecs/office_file_formats/ms-oshared
*/

rule OLE_Meta_Template_Injection : maldoc heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "OLE SummaryInformation Template property points to a remote http(s)/UNC path (remote-template injection, T1221)"
        reference   = "https://attack.mitre.org/techniques/T1221/"
        score       = "60"
    strings:
        $marker = "OLE-META-TEMPLATE-INJECTION" ascii
    condition:
        filesize < 16MB and $marker
}

rule OLE_Meta_AppName_Equation : maldoc heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "OLE SummaryInformation AppName is Equation Editor (CVE-2017-11882 / CVE-2018-0802 EQNEDT32 vector)"
        reference   = "https://nvd.nist.gov/vuln/detail/CVE-2017-11882"
        score       = "70"
    strings:
        $marker = "OLE-META-APPNAME-EQUATION" ascii
    condition:
        filesize < 16MB and $marker
}

rule OLE_Meta_FreshDoc_Stomp : maldoc heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "OLE SummaryInformation shows a fresh/VBA-stomped document (RevNumber 0/1 and zero total editing time)"
        reference   = "https://learn.microsoft.com/openspecs/office_file_formats/ms-oshared"
        score       = "40"
    strings:
        $rev  = "OLE-META-REVISION-ZERO" ascii
        $edit = "OLE-META-EDITTIME-ZERO" ascii
    condition:
        filesize < 16MB and $rev and $edit
}
