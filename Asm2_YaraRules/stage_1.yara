rule Stage1_VBA_Macro_Execution {
meta:
    description = "Detects suspicious VBA macro execution in Microsoft Office document"
    author = "Tran Anh Thu Pham"
    date = "2025-02-04"
    reference = "Stage 1"
    category = "Initial Access"

strings:
    // Common VBA function names used in macro-based malware
    $macro1 = "AutoOpen" nocase wide
    $macro2 = "Document_Open" nocase wide
    $macro3 = "Workbook_Open" nocase wide
    $macro4 = "Shell.Application" nocase wide
    $macro5 = "WScript.Shell" nocase wide
    $macro6 = "CreateObject" nocase wide
    $macro7 = "cmd.exe /c" nocase wide
    $macro8 = "powershell" nocase wide

    // Suspicious encoded PowerShell commands
    $encoded_ps1 = "powershell -e" nocase wide
    $encoded_ps2 = "Invoke-Expression" nocase wide
    $encoded_ps3 = "FromBase64String" nocase wide

    // Potential payload delivery URLs 
    $url = /https?:\/\/[a-zA-Z0-9._\-\/]+/ nocase wide ascii

condition:
    any of ($macro*) or any of ($encoded_ps*) or $url
}
