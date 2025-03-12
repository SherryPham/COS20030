import "pe"
import "math"

rule Stage2_Payload_Execution {
meta:
    description = "Detect malicious PE payload execution and C2 communication"
    author = "Tran Anh Thu Pham"
    date = "2025-02-04"
    reference = "Stage 2"
    category = "Execution and Persistence"

strings:
    // Detect suspicious function names or variables used in malware
    $malware_func1 = "dhrvgranit" nocase wide
    $malware_func2 = "load_pro" nocase wide
    $malware_func3 = "new_ob_data" nocase wide
    $malware_func4 = "run_malware" nocase wide
    $malware_func5 = "execute_payload" nocase wide

    // Detect command execution patterns
    $cmd_exec1 = "cmd.exe /c" nocase wide 
    $cmd_exec2 = "powershell" nocase wide
    $cmd_exec3 = "rundll32.exe" nocase wide  // Fixed typo
    $cmd_exec4 = "schtasks.exe /create" nocase wide
    $cmd_exec5 = "reg add" nocase wide

    // Detect C2 communication patterns 
    $c2_url1 = /https?:\/\/[a-zA-Z0-9._\-\/]+/ nocase wide ascii
    $c2_url2 = "POST /gate.php" nocase wide 
    $c2_url3 = "GET /payload.bin" nocase wide
    $c2_url4 = "User-Agent: Mozilla/5.0" nocase wide  // Detects common C2 UA spoofing

condition:
    pe.is_pe and (any of ($malware_func*) or any of ($cmd_exec*) or any of ($c2_url*))
}
