rule PKZIP_Archive_1_Flexible_Pattern {
    meta:
        description = "Detects PKZIP_archive_1 variants using structural anchors and common metadata found in CSV analysis."
        author = "Security Researcher"
        date = "2024-05-22"

    strings:
        /* Pattern Breakdown:
           50 4b 03 04       : ZIP Signature
           ?? 00             : Version (Flexible: 0a or 14)
           ?? ??             : Bit Flags (Variable)
           ?? 00             : Compression (Flexible: 00 or 08)
           [4]               : Skip 4 bytes (Last Mod Time/Date - highly variable)
           [4]               : Skip 4 bytes (CRC-32 - unique to content)
           [8]               : Skip 8 bytes (Compressed/Uncompressed Size)
           ?? 00 00 00       : Filename length (Variable) and Extra Field length (00 00)
        */
        
        $pk_structure = { 50 4b 03 04 ?? 00 ?? ?? ?? 00 [4] [4] [8] ?? 00 00 00 }

        // Optional: Common filename prefixes found in the PKZIP_archive_1 category
        $trash_prefix = "[trash]/"
        $content_prefix = "[Content_Types]"
        $office_prefix = "word/"
        $ppt_prefix = "ppt/"

    condition:
        // Rule must match at the beginning of the file
        $pk_structure at 0 and 
        
        // Ensure the filename starts at offset 30 and matches one of the observed prefixes
        // This ensures we only catch files similar to the analyzed dataset
        (
            $trash_prefix at 30 or 
            $content_prefix at 30 or 
            $office_prefix at 30 or 
            $ppt_prefix at 30
        )
}