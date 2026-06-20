/*
  OLEID indicator rules -- score yarad's oleid-style structural markers.

  yarad's extract.fromOLEIndicators surfaces two structural indicators that
  oletools' oleid reports (oleid.py) as synthetic marker streams, invisible in
  the raw OLE2 bytes:

    - "OLEID-OBJECTPOOL" -- the document carries an ObjectPool storage, i.e. it
      embeds OLE objects (oleid.py:400). A common lure mechanism (embedded
      packager / OLE object that drops or launches a payload).
    - "OLEID-FLASH" -- an embedded Shockwave Flash (SWF) object (oleid.py:490),
      a long-lived exploit-delivery vector.

  Both are presence indicators, NOT conclusive on their own -- a benign document
  can legitimately embed an OLE object. So these are scored LOW; the value is
  that they STACK with other signals (macros, external rels, suspicious
  keywords) the same scan already surfaces. Matching the marker prefix is
  zero-FP by construction (the literal is only ever emitted by yarad).

  Heuristic, tagged `suspicious heuristic` so yara.lua routes them to
  YARA_SUSPICIOUS (operator-tunable).

  Reference: https://github.com/decalage2/oletools/wiki/oleid
*/
rule OLEID_ObjectPool : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document embeds OLE objects (ObjectPool storage present) -- oleid indicator"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "10"
    strings:
        $marker = "OLEID-OBJECTPOOL" ascii
    condition:
        filesize < 16MB and $marker
}

rule OLEID_Flash : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Document embeds a Shockwave Flash (SWF) object -- oleid indicator"
        reference   = "https://github.com/decalage2/oletools/wiki/oleid"
        score       = "30"
    strings:
        $marker = "OLEID-FLASH" ascii
    condition:
        filesize < 16MB and $marker
}
