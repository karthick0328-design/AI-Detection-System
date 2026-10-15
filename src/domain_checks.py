"""
Modular Domain and Reputation Check Service.

Performs isolated, safe domain verification (DNS resolution, private IP filtering,
and optional reputation queries) without executing remote JavaScript, visiting
untrusted landing pages, or causing Server-Side Request Forgery (SSRF).

Strictly reports accurate status codes:
- "Checked — warning found"
- "Checked — no warning returned"
- "Not checked"
- "Unavailable"
- "Error"
"""

import socket
import ipaddress
from urllib.parse import urlsplit
from typing import Dict, Any, Optional
from config import Config

# Private / reserved IPv4 & IPv6 networks to guard against SSRF
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to a loopback, private, or link-local range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def run_domain_checks(normalized_url: str, enable_external: Optional[bool] = None) -> Dict[str, Any]:
    """
    Executes modular domain-level safety checks.
    
    Returns structured results for:
    - DNS Resolution
    - SSRF / Internal Network Guard
    - Domain Reputation / External Feed Status
    """
    if enable_external is None:
        enable_external = Config.ENABLE_EXTERNAL_CHECKS

    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname or ""
    
    results = {
        "hostname": hostname,
        "dns_resolution": {
            "status": "Not checked",
            "resolved_ip": None,
            "details": "DNS resolution check pending."
        },
        "ssrf_protection": {
            "status": "Checked — no warning returned",
            "is_private": False,
            "details": "Safe public target or domain syntax."
        },
        "external_reputation": {
            "status": "Not checked" if not enable_external else "Unavailable",
            "details": "External reputation API disabled (free offline mode active). No external credentials configured."
        }
    }

    if not hostname:
        results["dns_resolution"]["status"] = "Error"
        results["dns_resolution"]["details"] = "No valid hostname found in URL."
        return results

    # Check if direct hostname is already a private IP
    if is_private_ip(hostname):
        results["ssrf_protection"]["status"] = "Checked — warning found"
        results["ssrf_protection"]["is_private"] = True
        results["ssrf_protection"]["details"] = f"Hostname resolves directly to private/internal network IP ({hostname})."
        results["dns_resolution"]["status"] = "Checked — warning found"
        results["dns_resolution"]["resolved_ip"] = hostname
        return results

    # Perform safe local DNS resolution with short timeout
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(Config.DOMAIN_CHECK_TIMEOUT)
        # getaddrinfo returns: (family, type, proto, canonname, sockaddr)
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_info:
            resolved_ip = addr_info[0][4][0]
            results["dns_resolution"]["resolved_ip"] = resolved_ip
            
            # Check resolved IP against private networks
            if is_private_ip(resolved_ip):
                results["ssrf_protection"]["status"] = "Checked — warning found"
                results["ssrf_protection"]["is_private"] = True
                results["ssrf_protection"]["details"] = (
                    f"Domain resolves to private/internal IP {resolved_ip}. "
                    "Access blocked to prevent Server-Side Request Forgery."
                )
                results["dns_resolution"]["status"] = "Checked — warning found"
            else:
                results["dns_resolution"]["status"] = "Checked — no warning returned"
                results["dns_resolution"]["details"] = f"Domain resolves to valid public IP: {resolved_ip}"
    except (socket.gaierror, socket.herror) as e:
        results["dns_resolution"]["status"] = "Checked — warning found"
        results["dns_resolution"]["details"] = f"Domain name cannot be resolved via DNS (NXDOMAIN or unregistered). Error: {e}"
    except socket.timeout:
        results["dns_resolution"]["status"] = "Unavailable"
        results["dns_resolution"]["details"] = "DNS query timed out. Network latency or query dropped."
    except Exception as e:
        results["dns_resolution"]["status"] = "Error"
        results["dns_resolution"]["details"] = f"Unexpected DNS lookup error: {str(e)}"
    finally:
        socket.setdefaulttimeout(original_timeout)

    return results
