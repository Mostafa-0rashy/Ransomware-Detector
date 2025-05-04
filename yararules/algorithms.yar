rule algorithms
{
    meta:
        description = "Detects common encryption algorithms used in ransomware"
        score = 5 

    strings:
        $algo1 = "AES" ascii wide nocase
        $algo2 = "RSA" ascii wide nocase
        $algo3 = "DES" ascii wide nocase
        $algo4 = "3DES" ascii wide nocase
        $algo5 = "Blowfish" ascii wide nocase
        $algo6 = "Serpent" ascii wide nocase
        $algo7 = "Twofish" ascii wide nocase
        $algo8 = "CAST5" ascii wide nocase
        $algo9 = "IDEA" ascii wide nocase
        $algo10 = "Skipjack" ascii wide nocase
        $algo11 = "Camellia" ascii wide nocase
        $algo12 = "SEED" ascii wide nocase
        $algo13 = "GOST" ascii wide nocase

        $algo14 = "ChaCha" ascii wide nocase
        $algo15 = "ChaCha20" ascii wide nocase
        $algo16 = "Salsa" ascii wide nocase
        $algo17 = "Salsa20" ascii wide nocase


        $algo18 = "RC2" ascii wide nocase
        $algo19 = "RC4" ascii wide nocase
        $algo20 = "RC5" ascii wide nocase
        $algo21 = "RC6" ascii wide nocase

        $algo22 = "ARCFOUR" ascii wide nocase       // alias for RC4
        $algo23 = "ARCFOUR128" ascii wide nocase    // variant label (not standard)
        $algo24 = "ARCTWO" ascii wide nocase        // not real, likely fake
        $algo25 = "AES256X" ascii wide nocase       // fake/obfuscated
        $algo26 = "SuperEncryptor" ascii wide nocase // fake or tool-specific
        $algo27 = "UltraSafe" ascii wide nocase      // fake marketing name
        $algo28 = "EncryptX" ascii wide nocase       // obfuscated label

    condition:
        1 of ($algo*)
}

