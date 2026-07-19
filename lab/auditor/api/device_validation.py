"""Validation for device registration and scan targeting.

This module is the security boundary that replaced the fixed
`allowed_devices` whitelist when devices became user-registerable. It has no
DB or HTTP imports on purpose: auditor-api imports it at write time and
auditor-worker imports it again at execute time, so a row written by a buggy
or older API version is still refused before any command is built.
"""
import ipaddress
import re

# audit-network, per lab/docker-compose.yml. Nothing outside this is a legal
# target - including other private ranges.
ALLOWED_NETWORK = ipaddress.ip_network("172.30.0.0/24")

# The auditor is not an audit target.
INFRASTRUCTURE_HOSTS = frozenset(
    {"auditor-api", "auditor-database", "auditor-web", "auditor-worker"}
)

# Leading char must be alphanumeric: that is what stops a value like
# "--script=http-shellshock" from becoming a command-line FLAG in the argv list.
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")
TIERS = ("insecure", "partial", "hardened", "unknown")


class ValidationError(Exception):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


def validate_device_id(value: str) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.match(value):
        raise ValidationError(
            "device_id",
            "device_id must be lowercase alphanumeric with dashes, "
            "start with a letter or digit, and be at most 63 characters",
        )
    return value


def validate_host(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError("host", "host is required")

    # Try IP first. ipaddress parses octal/alternate forms that a regex would
    # treat as an unrelated string, which is the point of parsing rather than
    # pattern-matching.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    if address is not None:
        if address not in ALLOWED_NETWORK:
            raise ValidationError(
                "host", f"IP must be inside {ALLOWED_NETWORK} (audit-network)"
            )
        return value

    # Reject loopback aliases (localhost is a name for 127.0.0.1, which fails the
    # IP range check above).
    if value == "localhost":
        raise ValidationError(
            "host", "localhost is a loopback alias and cannot be a target"
        )

    # Reject any dotted or colon-separated form that is not a valid IP but looks
    # like one, so "0172.030.0.1" cannot slip through as a hostname. Only apply
    # this guard to strings that actually have dots or colons (the shape of IPs).
    if ("." in value or ":" in value) and re.fullmatch(r"[0-9a-fA-FxX.:]+", value):
        raise ValidationError("host", "host looks like an IP but is not a valid address")

    # glibc's getaddrinfo (used by nmap's resolver, curl, requests, etc.) does
    # not require dotted-quad notation: it also accepts a bare integer
    # ("134744072") or a 0x/0X-prefixed hex string ("0x8080808") and resolves
    # it as an IPv4 address via inet_aton semantics - both of those examples
    # resolve to 8.8.8.8. Neither form contains a "." or ":", so the guard
    # above never sees them, and NAME_PATTERN happily matches them because
    # they are valid lowercase-alphanumeric strings. A real container name is
    # never also a valid integer/hex literal, so reject any host that parses
    # cleanly as one with Python's own int-literal grammar before treating it
    # as a container name. Do not delete this thinking it is redundant with
    # NAME_PATTERN - it is the only thing that catches this bypass.
    try:
        int(value, 0)
    except ValueError:
        pass
    else:
        raise ValidationError(
            "host",
            "host is a bare integer or hex value, which resolves as an IP "
            "address via inet_aton semantics and is not accepted as a "
            "container name",
        )

    if value in INFRASTRUCTURE_HOSTS:
        raise ValidationError("host", f"{value} is infrastructure and cannot be a target")

    if not NAME_PATTERN.match(value):
        raise ValidationError(
            "host",
            "host must be a container name (lowercase alphanumeric with dashes) "
            f"or an IP inside {ALLOWED_NETWORK}",
        )
    return value


def validate_port(value: int, field: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(field, f"{field} must be an integer")
    if not 1 <= value <= 65535:
        raise ValidationError(field, f"{field} must be between 1 and 65535")
    return value


def validate_service_type(value: str) -> str:
    if value not in SERVICE_TYPES:
        raise ValidationError(
            "service_type", f"service_type must be one of {', '.join(SERVICE_TYPES)}"
        )
    return value
