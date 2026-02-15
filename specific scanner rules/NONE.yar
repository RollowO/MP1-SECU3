rule Detect_None_Type_Config {
    meta:
        description = "Detects text-based config files with flexible byte matching"
        author = "Gemini"
        category = "None_Type_Analysis"

    strings:
        // Matches "Con" followed by flexible bytes, then likely structural characters
        // Hex: 43 6F 6E [3-5 wildcard bytes] 69 67
        $config_start = { 43 6f 6e ?? ?? ?? [1-2] 69 67 }
        
        // Matches common newline/assignment patterns in text files
        $assignment = { 3d 20 } // ASCII: "= "

    condition:
        $config_start at 0 or $assignment
}

rule Detect_None_General_Fuzzy {
    meta:
        description = "Detects None-type files using structural anchors"
    
    strings:
        $anchor1 = { 43 6f 6e 66 } // "Conf"
        $anchor2 = { 61 74 69 6f 6e } // "ation"
        $hex_pattern = { 43 6f ?? ?? 20 5b ?? ?? 5d } // "Co.. [..]"

    condition:
        // Only trigger if at least 2 of these patterns are found near the start
        2 of them and for any i in (1..#anchor1): (@anchor1[i] < 100)
}