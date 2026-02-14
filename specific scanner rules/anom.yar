rule Exact_Cluster_PKZIP
{
    meta:
        description = "Matches only PKZIP files from identified CSV cluster"
        category = "Archive"
        precision = "High"

    condition:
        // ZIP Local File Header
        uint32(0) == 0x04034B50 and
        
        // Exact version used in cluster
        uint16(4) == 0x0014 and
        
        // Exact general purpose bit flag used in cluster
        uint16(6) == 0x0000 and
        
        // Exact compression method (Deflate)
        uint16(8) == 0x0008 and
        
        // Filename length tightly bounded (cluster fingerprint)
        uint16(26) > 0 and uint16(26) < 100 and
        
        // Extra field length consistent with cluster
        uint16(28) == 0
}
