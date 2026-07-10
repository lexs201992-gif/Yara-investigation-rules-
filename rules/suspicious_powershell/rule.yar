rule suspicious_powershell_encoded_command_v2
{
  meta:
    author = "lexs201992-gif"
    version = "2.0"
    description = "Detects suspicious encoded or obfuscated PowerShell execution patterns"
    severity = "high"
    tlp = "clear"
    mitre_attack = "T1059.001,T1027,T1140"

  strings:
    $p0 = "powershell" nocase ascii wide
    $p1 = "-enc " nocase ascii wide
    $p2 = "-encodedcommand" nocase ascii wide
    $p3 = "FromBase64String(" nocase ascii wide
    $p4 = "IEX(" nocase ascii wide
    $p5 = "Invoke-Expression" nocase ascii wide
    $p6 = "DownloadString(" nocase ascii wide
    $p7 = "Net.WebClient" nocase ascii wide
    $p8 = "Start-BitsTransfer" nocase ascii wide
    $p9 = "-windowstyle hidden" nocase ascii wide
    $p10 = "-nop" nocase ascii wide
    $p11 = "-noni" nocase ascii wide

  condition:
    $p0 and
    (
      (1 of ($p1,$p2) and 1 of ($p3,$p4,$p5)) or
      (1 of ($p6,$p7,$p8) and 1 of ($p9,$p10,$p11))
    )
}
