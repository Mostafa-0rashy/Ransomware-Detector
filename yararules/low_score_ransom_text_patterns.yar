rule low_score_ransom_text_patterns
{
    meta:
        description = "Detects low-confidence ransomware ransom note text patterns"
        score = 3  

    strings:
        $note1  = "backup" nocase ascii wide
        $note2  = "bitcoin" nocase ascii wide
        $note3  = "contact us" nocase ascii wide
        $note4  = "email us" nocase ascii wide
        $note5  = "passphrase" nocase ascii wide
        $note6  = "password" nocase ascii wide
        $note7  = "payment" nocase ascii wide
        $note8  = "personal ID" nocase ascii wide
        $note9  = "data leak" nocase ascii wide
        $note10 = "data breach" nocase ascii wide
        $note11 = "data theft" nocase ascii wide
        $note12 = "data recovery" nocase ascii wide
        $note13 = "data loss" nocase ascii wide
        $note14 = "data protection" nocase ascii wide
        $note15 = "data security" nocase ascii wide
        $note16 = "your documents" nocase ascii wide
        $note17 = "your photos" nocase ascii wide
        $note18 = "do not rename files" nocase ascii wide
        $note19 = "do not shut down" nocase ascii wide
        $note20 = "btc wallet" nocase ascii wide

    condition:
        any of ($note*)
}

