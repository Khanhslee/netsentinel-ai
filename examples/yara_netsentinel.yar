rule NetSentinel_beacon_d238fcd97016
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed beacon IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1071.001"
        mitre_technique = "T1071.001"
        date = "2026-10-29"
        severity = "critical"
        source_event = "5952c688a058"
    strings:
        $ioc_0 = "203.0.113.10" ascii nocase
        $ioc_1 = "203.0.113.10:8080" ascii nocase
    condition:
        any of them
}


rule NetSentinel_port_scan_f79ce4e459ec
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed port_scan IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1046"
        mitre_technique = "T1046"
        date = "2026-10-29"
        severity = "high"
        source_event = "1e684ac2848c"
    strings:
        $ioc_0 = "10.0.0.7" ascii nocase
        $ioc_1 = "10.0.0.50" ascii nocase
    condition:
        any of them
}


rule NetSentinel_nxdomain_storm_4873b1e0b3f8
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed nxdomain_storm IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1568.002"
        mitre_technique = "T1568.002"
        date = "2026-10-29"
        severity = "high"
        source_event = "a2ce06db6784"
    strings:
        $ioc_0 = "tkgnkuhmpxnhtqg.net" ascii nocase
        $ioc_1 = "amammhvambytjkdj.info" ascii nocase
        $ioc_2 = "cjevwgfarzqu.org" ascii nocase
        $ioc_3 = "gjrvqnvugbejwjcg.net" ascii nocase
        $ioc_4 = "gnjjzmqlwfaqzji.net" ascii nocase
        $ioc_5 = "hsmcaohzbnjuv.org" ascii nocase
        $ioc_6 = "hxuxqrwqebvtad.com" ascii nocase
        $ioc_7 = "jjfbdvnkamkox.info" ascii nocase
        $ioc_8 = "oubdtmjfmxkpt.info" ascii nocase
        $ioc_9 = "pdxmppxmoesoo.info" ascii nocase
        $ioc_10 = "pgerimpiysseyyk.net" ascii nocase
        $ioc_11 = "qtngthblmwkx.org" ascii nocase
        $ioc_12 = "vmgarmtjuhusknrf.org" ascii nocase
        $ioc_13 = "wwulweumpeldoxq.info" ascii nocase
        $ioc_14 = "ykbvcpxfckgobo.net" ascii nocase
    condition:
        any of them
}


rule NetSentinel_dns_tunneling_4d7b358d06fc
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed dns_tunneling IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1071.004"
        mitre_technique = "T1071.004"
        date = "2026-10-29"
        severity = "high"
        source_event = "abb0ed60aa74"
    strings:
        $ioc_0 = "tunnel.evil" ascii nocase
    condition:
        any of them
}


rule NetSentinel_dga_b21f027a106f
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed dga IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1568.002"
        mitre_technique = "T1568.002"
        date = "2026-10-29"
        severity = "high"
        source_event = "165a7ec67b03"
    strings:
        $ioc_0 = "amammhvambytjkdj.info" ascii nocase
        $ioc_1 = "cjevwgfarzqu.org" ascii nocase
        $ioc_2 = "gjrvqnvugbejwjcg.net" ascii nocase
        $ioc_3 = "gnjjzmqlwfaqzji.net" ascii nocase
        $ioc_4 = "hsmcaohzbnjuv.org" ascii nocase
        $ioc_5 = "hxuxqrwqebvtad.com" ascii nocase
        $ioc_6 = "jjfbdvnkamkox.info" ascii nocase
        $ioc_7 = "oubdtmjfmxkpt.info" ascii nocase
        $ioc_8 = "pgerimpiysseyyk.net" ascii nocase
        $ioc_9 = "qtngthblmwkx.org" ascii nocase
        $ioc_10 = "tkgnkuhmpxnhtqg.net" ascii nocase
        $ioc_11 = "vmgarmtjuhusknrf.org" ascii nocase
        $ioc_12 = "wwulweumpeldoxq.info" ascii nocase
        $ioc_13 = "ykbvcpxfckgobo.net" ascii nocase
    condition:
        any of them
}


rule NetSentinel_exfiltration_7b98db61c746
{
    meta:
        author = "NetSentinel AI - Meta Muse Wonder"
        description = "Observed exfiltration IOC hunt; validate matches with endpoint telemetry"
        mitre_attck = "T1041"
        mitre_technique = "T1041"
        date = "2026-10-29"
        severity = "medium"
        source_event = "41c8483929e7"
    strings:
        $ioc_0 = "198.51.100.5" ascii nocase
        $ioc_1 = "198.51.100.5:443" ascii nocase
    condition:
        any of them
}
