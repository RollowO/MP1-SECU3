rule Detect_MP3_Patterns_from_CSV
{
    meta:
        description = "Detects MP3 files based on patterns from File023 and File063 in CSV"
        file_type = "Audio/MP3"

    strings:
        // ID3 Magic Header (ASCII 'ID3') - Common to both files
        $id3_magic = { 49 44 33 }

        // Pattern Based on File023:
        // We use ?? for the version and size bytes which vary between files.
        // This allows detection even if metadata changes slightly.
        $file23_similar = { 49 44 33 00 ?? ?? 00 00 00 ?? 00 ?? 00 ff ff 08 }

        // Pattern Based on File063:
        // This file contains an ASCII-like header "1.4\r%".
        // We capture this unique pattern while allowing for tailing variations.
        $file63_similar = { 49 44 33 31 2e 34 0d 25 ?? ?? ?? ?? ?? ?? ?? }

        // Standard MPEG Audio Frame Sync (Fallback):
        // Often follows the ID3 tag. FF FB or FF FA are standard starts.
        $mpeg_sync = { FF FB } 
        $mpeg_sync_alt = { FF FA }

    condition:
        // 1. Must start with ID3 magic to avoid scanning unrelated files (like docs/executables)
        $id3_magic at 0 and 
        (
            // 2. Must match one of the structural patterns identified in the CSV
            $file23_similar at 0 or 
            $file63_similar at 0 or
            
            // 3. Or find a standard MPEG sync word shortly after the header
            // (Handles similarity if the first 15-20 bytes change completely)
            for any i in (1..#mpeg_sync) : ( @mpeg_sync[i] < 2048 ) or
            for any i in (1..#mpeg_sync_alt) : ( @mpeg_sync_alt[i] < 2048 )
        )
}