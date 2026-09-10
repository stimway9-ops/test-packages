rule COMPANY_MALWARE_TEST
{
    meta:
        author      = "security-team"
        version     = "1.0"
        created     = "2026-09-03"
        description = "PoC rule for CI/CD pipeline validation - detects synthetic test payload strings"
        reference   = "Internal SEC-POC-0001"
        family      = "poc-synthetic"

    strings:
        $s1 = "COMPANY-MALWARE-TEST"
        $s2 = "MALWARE-PAYLOAD"

    condition:
        all of them
}
