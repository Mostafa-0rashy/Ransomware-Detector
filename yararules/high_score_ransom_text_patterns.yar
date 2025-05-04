rule high_score_ransom_text_patterns
{
    meta:
        description = "Detects common ransomware ransom note text patterns"
        score = 6   

    strings:
        $note1  = "decrypt" nocase ascii wide
        $note2  = "decrypted" nocase ascii wide
        $note3  = "decryption" nocase ascii wide
        $note4  = "decrypting" nocase ascii wide
        $note5  = "decryptor" nocase ascii wide
        $note6  = "decrypts" nocase ascii wide
        $note7  = "encrypt" nocase ascii wide
        $note8  = "encrypted" nocase ascii wide
        $note9  = "encrypting" nocase ascii wide
        $note10 = "encryptor" nocase ascii wide
        $note11 = "encryption" nocase ascii wide
        $note12 = "key" nocase ascii wide
        $note13 = "keys" nocase ascii wide
        $note14 = "lock" nocase ascii wide
        $note15 = "locked" nocase ascii wide
        $note16 = "ransom" nocase ascii wide
        $note17 = "ransomware" nocase ascii wide
        $note18 = "recover" nocase ascii wide
        $note19 = "restore" nocase ascii wide
        $note20 = "restore your data" nocase ascii wide
        $note21 = "unlock" nocase ascii wide
        $note22 = "we have locked your files" nocase ascii wide
        $note23 = "do not try to recover" nocase ascii wide
        $note24 = "your files have been encrypted" nocase ascii wide
        $note25 = "proof of decryption" nocase ascii wide
        $note26 = "extortion" nocase ascii wide  //Mosawma
        $note27 = "tor browser" nocase ascii wide //deep web

    condition:
        any of ($note*)
}

