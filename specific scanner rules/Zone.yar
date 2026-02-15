rule ZoneAlam_Hex_Flexible {
    meta:
        description = "Detects ZoneAlam files using hex pattern with wildcards for flexibility"
    strings:
        // Uses ?? for bytes 2, 16, and 17 to allow for minor file variations
        $zone_header = { 
            4d 5a ?? 00 03 00 00 00 04 00 00 00 ff ff 00 00 
            ?? ?? 00 00 00 00 00 00 40 00 
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
        }
    condition:
        $zone_header at 0
}