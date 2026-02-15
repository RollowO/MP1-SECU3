rule ZoneAlam_Flexible_Detection {
    meta:
        description = "Catches ZoneAlam variants by looking for MZ header without the standard DOS stub"
    strings:
        $mz = { 4D 5A }
        $standard_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and not $standard_stub
}