rule ZoneAlam_Structural_Pattern {
    meta:
        description = "Detects ZoneAlam variants by checking structural header constants"
        similarity_flexibility = "High - ignores non-structural byte changes"
    condition:
        // 1. Core MZ Signature (4D 5A)
        uint16(0) == 0x5a4d and
        
        // 2. Structural Identifiers (Offsets 4 and 8)
        // These are consistent across all ZoneAlam samples but vary in other EXEs
        uint16(4) == 0x0003 and // Pages in file
        uint16(8) == 0x0004 and // Header size in paragraphs
        
        // 3. Environment Constants (Offsets 12 and 24)
        uint16(12) == 0xffff and // Max extra paragraphs
        uint16(24) == 0x0040 and // Relocation table offset
        
        // 4. Zero-Padding Validation (Offset 32-48)
        // Differentiates from standard Windows PEs which have a DOS stub message here
        uint32(32) == 0x00000000 and
        uint32(44) == 0x00000000
}