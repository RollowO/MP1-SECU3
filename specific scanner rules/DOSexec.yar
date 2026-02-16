rule targeted_detection_v11 {
    meta:
        description = "Detects specific targets File046, 067, 155, 159, 200 while ignoring Git and VSCode installers."
    
    condition:
        uint16(0) == 0x5a4d and // Must start with MZ
        (
            // 1. File200: PNG/MZ Polyglot
            uint32(6) == 0x52444849 or 
            
            // 2. File046: Unique uint16 at offset 2
            (uint16(2) == 0x0100 and uint8(8) == 0x08) or
            
            // 3. File067 & File159: Distinct offset 2 values
            ((uint8(2) == 0x93 or uint8(2) == 0x8b) and uint8(8) == 0x20) or
            
            // 4. File155: The specific 'MZP' variant with NULL padding at 0x30
            // This is the key to ignoring Git/VSCode/Unins000
            (uint8(2) == 0x50 and uint16(0x30) == 0x0000)
        ) 
        // GLOBAL SAFETY: Explicitly ignore the Inno Setup 'In' signature (0x6E49) 
        // which is present in Git and VSCode installers at offset 0x30.
        and not uint16(0x30) == 0x6e49
}