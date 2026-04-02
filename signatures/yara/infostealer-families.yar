/*
  YARA signatures for common infostealer families
  Created: 2026-04-02
*/

rule RedLine_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects RedLine infostealer family indicators"
    family = "RedLine"
    severity = "high"
  strings:
    $s1 = "RedLine" nocase
    $s2 = "Yandex\\YaAddon" nocase
    $s3 = "Login Data" nocase
    $s4 = "%appdata%\\\\browsers" nocase
  condition:
    any 2 of them
}

rule Raccoon_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Raccoon infostealer family indicators"
    family = "Raccoon"
    severity = "high"
  strings:
    $s1 = "raccoon" nocase
    $s2 = "machineId" nocase
    $s3 = "ews_stealer" nocase
    $s4 = "configId" nocase
  condition:
    any 2 of them
}

rule Vidar_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Vidar infostealer family indicators"
    family = "Vidar"
    severity = "high"
  strings:
    $s1 = "vidar" nocase
    $s2 = "wallet.dat" nocase
    $s3 = "\\Authy\\" nocase
    $s4 = "2fa_codes" nocase
  condition:
    any 2 of them
}

rule Lumma_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Lumma infostealer family indicators"
    family = "Lumma"
    severity = "high"
  strings:
    $s1 = "lumma" nocase
    $s2 = "LummaC2" nocase
    $s3 = "lid=" nocase
    $s4 = "hwid=" nocase
  condition:
    any 2 of them
}

rule StealC_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects StealC infostealer family indicators"
    family = "StealC"
    severity = "high"
  strings:
    $s1 = "stealc" nocase
    $s2 = "gate.php" nocase
    $s3 = "browsers.zip" nocase
  condition:
    any 2 of them
}

rule Rhadamanthys_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Rhadamanthys infostealer family indicators"
    family = "Rhadamanthys"
    severity = "high"
  strings:
    $s1 = "rhadamanthys" nocase
    $s2 = "sinmice" nocase
    $s3 = "image_ocr" nocase
    $s4 = "seed_phrase" nocase
  condition:
    any 2 of them
}

rule AtomicAMOS_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Atomic/AMOS macOS infostealer family indicators"
    family = "Atomic/AMOS"
    severity = "high"
  strings:
    $s1 = "atomic" nocase
    $s2 = "osascript" nocase
    $s3 = "Keychain" nocase
    $s4 = "AppleScript" nocase
  condition:
    any 2 of them
}

rule Poseidon_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Poseidon infostealer family indicators"
    family = "Poseidon"
    severity = "high"
  strings:
    $s1 = "poseidon" nocase
    $s2 = "stealer_mac" nocase
    $s3 = "security find-generic-password" nocase
  condition:
    any 2 of them
}

rule Banshee_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Banshee infostealer family indicators"
    family = "Banshee"
    severity = "high"
  strings:
    $s1 = "banshee" nocase
    $s2 = "xprotect" nocase
    $s3 = "login.keychain-db" nocase
  condition:
    any 2 of them
}

rule ACRStealer_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects ACR Stealer family indicators"
    family = "ACR Stealer"
    severity = "high"
  strings:
    $s1 = "acr_stealer" nocase
    $s2 = "dead_drop" nocase
    $s3 = "Steam Community" nocase
    $s4 = "Google Forms" nocase
  condition:
    any 2 of them
}

rule Amatera_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects Amatera infostealer family indicators"
    family = "Amatera"
    severity = "high"
  strings:
    $s1 = "amatera" nocase
    $s2 = "installfix" nocase
    $s3 = "cdn_c2" nocase
    $s4 = "dynamic_api" nocase
  condition:
    any 2 of them
}

rule MetaStealer_Stealer {
  meta:
    author = "OpenAI Codex"
    description = "Detects MetaStealer family indicators"
    family = "MetaStealer"
    severity = "high"
  strings:
    $s1 = "metastealer" nocase
    $s2 = "meta_grab" nocase
    $s3 = "dmg_payload" nocase
  condition:
    any 2 of them
}
