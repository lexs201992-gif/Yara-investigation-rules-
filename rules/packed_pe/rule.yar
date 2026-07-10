import "pe"

rule packed_pe_high_entropy_sections_v2
{
  meta:
    author = "lexs201992-gif"
    version = "2.0"
    description = "Detects likely packed PE by entropy, suspicious section names, and import sparsity"
    severity = "medium"
    tlp = "clear"
    mitre_attack = "T1027"

  strings:
    $sec_upx0 = "UPX0" ascii
    $sec_upx1 = "UPX1" ascii
    $sec_aspack = ".aspack" ascii
    $sec_petite = ".petite" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.number_of_sections >= 3 and
    (
      for any i in (0..pe.number_of_sections - 1):
        (pe.sections[i].entropy >= 7.3 and pe.sections[i].raw_data_size > 0x1800)
    ) and
    (
      1 of ($sec_*) or pe.number_of_imported_functions < 25
    )
}
