import ssl

# device-partial intentionally serves a 1024-bit/SHA-1 cert to model a
# legacy/vulnerable device. Modern OpenSSL's default security level (2)
# refuses to load such a key (EE_KEY_TOO_SMALL) -- setting OPENSSL_CONF
# has no effect here because CPython's ssl module skips OpenSSL's
# config-file auto-loading. Patch load_cert_chain to relax the security
# level on the context first; device-hardened is unaffected since its
# strength comes from actually using a strong 2048-bit/SHA-256 key, not
# from this gate. See docs/errors/006-openssl-seclevel-rejects-weak-1024bit-cert.md.
_original_load_cert_chain = ssl.SSLContext.load_cert_chain


def _relaxed_load_cert_chain(self, certfile, keyfile=None, password=None):
    try:
        self.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return _original_load_cert_chain(self, certfile, keyfile, password)


ssl.SSLContext.load_cert_chain = _relaxed_load_cert_chain
