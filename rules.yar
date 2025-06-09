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


