import "pe"
import "math"

// Rule: FileHeaderIndicators
// Purpose: Check for suspicious PE file header characteristics that may indicate malware
// Checks:
// - Suspicious timestamp ranges (before 1992 or after 2012)
// - Unusual number of sections (less than 1 or more than 8)
// - Presence of symbol table (uncommon in modern PE files)
// - Suspicious byte order flags
// - Stripped relocation information
rule FileHeaderIndicators {
    meta:
        description = "Analyzes PE file headers for potential malware indicators and suspicious modifications"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.is_pe and (
            (pe.timestamp < 694224000) or (pe.timestamp > 1325376000) or  // Check for suspicious timestamps
            (pe.number_of_sections < 1) or (pe.number_of_sections > 8) or  // Check for abnormal section counts
            (pe.pointer_to_symbol_table > 0) or                           // Check for symbol table presence
            (pe.characteristics & pe.BYTES_REVERSED_HI != 0) or           // Check for suspicious byte ordering
            (pe.characteristics & pe.BYTES_REVERSED_LO != 0) or
            (pe.characteristics & pe.RELOCS_STRIPPED == 1)                // Check for stripped relocations
        )
}

// Rule: PEOptionalHeaderVersionAttributes
// Purpose: Verify version information in PE optional header against known good values
// Checks:
// - Linker version combinations
// - OS version combinations
// - Image version combinations
// Triggers if versions don't match common legitimate values
rule PEOptionalHeaderVersionAttributes {
    meta:
        description = "Identifies potentially malicious PE files by analyzing version information in the optional header"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.is_pe and
        // Check for invalid linker versions
        not (
            pe.linker_version.major == 8 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 9 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 7 and pe.linker_version.minor == 10 or
            pe.linker_version.major == 10 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 6 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 5 and pe.linker_version.minor == 10 or
            pe.linker_version.major == 5 and pe.linker_version.minor == 12 or
            pe.linker_version.major == 5 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 2 and pe.linker_version.minor == 25 or
            pe.linker_version.major == 2 and pe.linker_version.minor == 0 or
            pe.linker_version.major == 3 and pe.linker_version.minor == 10
        )
        and
        // Check for invalid OS versions
        not (
            pe.os_version.major == 4 and pe.os_version.minor == 0 or
            pe.os_version.major == 6 and pe.os_version.minor == 1 or
            pe.os_version.major == 5 and pe.os_version.minor == 0 or
            pe.os_version.major == 5 and pe.os_version.minor == 1 or
            pe.os_version.major == 5 and pe.os_version.minor == 2 or
            pe.os_version.major == 6 and pe.os_version.minor == 0
        )
        and
        // Check for invalid image versions
        not (
            pe.image_version.major == 0 and pe.image_version.minor == 0 or
            pe.image_version.major == 6 and pe.image_version.minor == 1 or
            pe.image_version.major == 5 and pe.image_version.minor == 1 or
            pe.image_version.major == 5 and pe.image_version.minor == 2 or
            pe.image_version.major == 6 and pe.image_version.minor == 0 or
            pe.image_version.major == 8 and pe.image_version.minor == 0 or
            pe.image_version.major == 5 and pe.image_version.minor == 0 or
            pe.image_version.major == 1 and pe.image_version.minor == 0 or
            pe.image_version.major == 9 and pe.image_version.minor == 0 or
            pe.image_version.major == 4 and pe.image_version.minor == 0
        )
}

// Rule: PEOptionalHeaderSizeAttributes
// Purpose: Detect suspicious size relationships between PE components
// Checks for unrealistic ratios between:
// - Code size vs file size
// - Initialized data size vs file size
// - Uninitialized data size vs file size
// - Image size vs file size
// - Headers size vs file size
rule PEOptionalHeaderSizeAttributes {
    meta:
        description = "Evaluates PE file size attributes to detect anomalies and potential tampering"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.is_pe and (
            (pe.size_of_code \ filesize > 1) or                          // Code size shouldn't exceed file size
            (pe.size_of_initialized_data \ filesize > 3) or              // Initialized data size check
            (pe.size_of_uninitialized_data \ filesize > 1) or           // Uninitialized data size check
            (pe.size_of_image \ filesize > 8) or                        // Image size ratio check
            (pe.size_of_headers \ filesize > 0)                         // Headers size check
        )
}

// Rule: PEOptionalHeaderLocationAttributes
// Purpose: Check for suspicious memory layout configurations
// Examines ratios between:
// - Code base address vs file size
// - Data base address vs file size
// - Entry point vs file size
rule PEOptionalHeaderLocationAttributes {
    meta:
        description = "Examines PE file memory layout attributes for suspicious configurations"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.is_pe and (
            (pe.base_of_code \ filesize > 2) or                         // Suspicious code base location
            (pe.base_of_data \ filesize > 3) or                         // Suspicious data base location
            (pe.entry_point \ filesize > 2)                             // Suspicious entry point location
        )
}

// Rule: PEOptionalHeaderMiscellaneousAttributes
// Purpose: Check for unusual PE header values that are typically zero in legitimate files
// Examines:
// - Loader flags (should be 0)
// - Number of RVA and sizes (should be 16)
// - Win32 version value (should be 0)
rule PEOptionalHeaderMiscellaneousAttributes {
    meta:
        description = "Detects unusual PE header configurations that may indicate malware"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.is_pe and (
            pe.loader_flags != 0 or                                      // Loader flags should be zero
            pe.number_of_rva_and_sizes != 16 or                         // Should always be 16 for normal PE files
            pe.win32_version_value != 0                                 // Should be zero in normal PE files
        )
}

// Rule: PESectionRules
// Purpose: Identify suspicious section characteristics
// Checks for:
// - Empty sections
// - Unrealistic virtual vs raw size ratios
// - Invalid line number pointers
// - Suspicious section characteristics
// - Abnormal entropy values
rule PESectionRules {
    meta:
        description = "Identifies suspicious PE section characteristics often associated with malware"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        for any i in ( 0 .. pe.number_of_sections - 1 ) : (
            (pe.sections[i].raw_data_size == 0) or                      // Check for empty sections
            (pe.sections[i].virtual_size \ pe.sections[i].raw_data_size) > 10 or  // Check for suspicious size ratios
            (pe.sections[i].virtual_size < pe.sections[i].raw_data_size) or      // Virtual size should be >= raw size
            (pe.sections[i].pointer_to_line_numbers != 0) or            // Should be zero in modern PE files
            (pe.sections[i].characteristics & 0x00000080 != 0) or       // Check for suspicious characteristics
            (pe.sections[i].characteristics & 0x10000000 != 0) or
            (math.entropy(0, filesize) < 1) or (math.entropy(0, filesize) > 7)  // Check for abnormal entropy
        )
}

// Rule: PESectionEntropyRules
// Purpose: Detect potential encryption or packing through entropy analysis
// Checks:
// - High entropy virtual address flag
// - Section-specific entropy values (> 6.9 indicates potential encryption/packing)
rule PESectionEntropyRules {
    meta:
        description = "Analyzes PE section entropy to detect potential encryption or packing"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        pe.HIGH_ENTROPY_VA != 0 or for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 6.9  // Check for high entropy sections
        )
}

// Rule: RSRCRules
// Purpose: Check for suspicious resource section characteristics
// Examines:
// - Resource language settings that may indicate automated malware creation
rule RSRCRules {
    meta:
        description = "Examines PE resource attributes for anomalies typical in malware"
        author = "Tran Anh Thu Pham"
        date = "2025-04-02"
        reference = "https://sansorg.egnyte.com/dl/zdmLYMKnP1"
    condition:
        for any resource in pe.resources: (
            (resource.language & 0xF000) >> 12 == 0                     // Check for suspicious resource language settings
        )
}