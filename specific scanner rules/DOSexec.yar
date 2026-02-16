rule targeted_detection_v13 {
    meta:
        description = "Detects specific targets File046, 067, 155, 159, 200 using compatible 32-bit identifiers."
    
    condition:
        // 1. File200: PNG/MZ Polyglot (IHDR at offset 6)
        (uint32(0) == 0x00005a4d and uint32(6) == 0x52444849) or

        // 2. File046: 12-byte precision (Bytes: 4D 5A 00 01 01 00 00 00 08 00 10 00)
        (uint32(0) == 0x01005a4d and uint32(4) == 0x00000001 and uint32(8) == 0x00100008) or

        // 3. File067: 12-byte precision (Bytes: 4D 5A 93 00 03 00 00 00 20 00 00 00)
        (uint32(0) == 0x00935a4d and uint32(4) == 0x00000003 and uint32(8) == 0x00000020) or

        // 4. File159: 12-byte precision (Bytes: 4D 5A 8B 00 03 00 00 00 20 00 00 00)
        (uint32(0) == 0x008b5a4d and uint32(4) == 0x00000003 and uint32(8) == 0x00000020) or

        // 5. File155: 12-byte precision + Installer Shield
        (
            uint32(0) == 0x00505a4d and 
            uint32(4) == 0x00000002 and 
            uint32(8) == 0x000f0004 and 
            not uint16(0x30) == 0x6e49 // Excludes Git/VSCode/unins000 ('In' at 0x30)
        )
}