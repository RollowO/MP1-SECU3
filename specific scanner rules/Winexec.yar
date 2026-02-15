rule Windows_Executable_Custom_Patterns {
    meta:
        description = "Detects Windows_executable files from the analyzed dataset using flexible patterns"
        author = "AI Assistant"
        date = "2024-05-23"

    strings:
        // Pattern 1: Detects JFIF/EXIF masquerading variants
        // Uses wildcards for the version/type bytes and a jump to find the consistent quantization table
        $jfif_masquerade = { ff ?? ff ?? 00 10 [0-8] (4a 46 49 46 | 45 58 49 46) [0-10] ff db 00 43 00 08 06 06 07 }

        // Pattern 2: Detects Modified DOS headers (e.g., ff fb instead of 4d 5a)
        // Matches the standard DOS structure starting from the 3rd byte
        $modified_dos = { ?? ?? 90 00 03 00 00 00 04 00 ?? ?? ff ff 00 00 b8 }

        // Pattern 3: Detects the specific PNG/IHDR hybrid masquerade
        $png_ihdr_masquerade = { ff d8 ff ?? ?? ?? ?? 49 48 44 52 }

    condition:
        any of them
}