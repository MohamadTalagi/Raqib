rule HardcodedPassword
{
    meta:
        description = "Detects a hardcoded admin password value baked into firmware config"
        severity = "high"
    strings:
        $default_pass = "admin_pass=admin"
        $weak_pass = "admin_pass=Ch4ng3d-Bu7-W3ak"
    condition:
        any of them
}

rule EmbeddedAPIKey
{
    meta:
        description = "Detects an embedded API key string in firmware config"
        severity = "high"
    strings:
        $key = /api_key=sk-[A-Za-z0-9\-]+/ ascii
    condition:
        $key
}

rule PrivateKeyFile
{
    meta:
        description = "Detects an embedded PEM private key inside firmware"
        severity = "critical"
    strings:
        $pem = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_ec = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}
