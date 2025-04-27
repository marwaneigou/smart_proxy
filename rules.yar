rule TestPDF
{
    strings:
        $pdf = "%PDF"
    condition:
        $pdf
}

rule TestEXE
{
    strings:
        $mz = "MZ"
    condition:
        $mz
}

rule SuspiciousBase64
{
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        $b64
}
