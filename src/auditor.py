import ssl # Python's built-in SSL/TLS library for speaking TLS to a server. Same OpenSSL library browsers use
import socket # handles raw network connection; before TLS can even happen, we need a basic TCP connection to server
import json # for writing scan results to a JSON file
import csv # for writing scan reults to a CSV file
import datetime # for timestamping reports
from pathlib import Path # clean/modern way to handle file paths in Python, works on any OS
import logging

# configure logging to show timestamps and log level
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path("artifacts/release") # defines where all output files go
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True) # creates directory automatically when script runs if it doesnt already exist


WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
"""
Deprecated TLS/SSL protocol versions that are conisdered insecure.

TLSv1 and TLSv1.1 were officially deprecated by IETF in 2021 (RFC 8996) and contain known 
design flaws that can be exploited by a network attacker. 
SSLv2 and SSLv3 are completely broken and have been deprecated for over a decade.

Any server still accepting these versions will be flagged.
Modern standards: TLS 1.2 and TLS 1.3
"""


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH", "AES128-SHA"
}
"""
Cipher suite keywords associated with weak or broken encryption.

RC4 -       Stream cipher proven mathematically broken, traffic can be decrypted.
DES -       Key size too small, cna be brute-forced in hours.
3DES -      Three rounds of DES, still considered too weak by modern standards.
MD5 -       Cryptographic hash with known collision vulnerabilities.
NULL -      No encryption at all, connection is sent in plaintext.
EXPORT -    Intentionally weakened ciphers from 1990s US export regulations.
anon -      Anonymous cipher suites with no server authentication.
ADH -       Anonymous Diffie-Hellman, no authentication, vulnerable to MITM.
AECDH -     Anonymous Elliptic Curve Diffie-Hellman, same problem as ADH.

Modern standards: AES-GCM, ChaCha20-Poly1305, ECDHE key exchange.
"""

def scan_host(hostname: str, port: int = 443) -> dict:
    """
    Connect to a host and inspect its TLS configuration.

    Opens a TCP socket to the target, wraps it in a TLS handshake,
    and extracts the protocol version, cipher suite, and certificate 
    details the server presented during negotiation.

    Args:
        hostname: The target domain to scan (e.g. 'google.com')
        port: The port to connect on, defaults to 443 (standards HTTPS)

    Returns:
        A dictionary containing the scan results with the following keys:
        - hostname: the target that was scanned
        - port: the port used
        - protocol: TLS protocol version the server agreed to
        - cipher: cipher suite name negotiated during the handshake
        - cert_subject: who the certificate was issued to
        - cert_issuer: who signed the certificate
        - cert_expiry: when the certificate expires
        - timestamp: when this scan was performed
    """

    # SSL context object; rulebook for how the TLS connection should behave
    logger.info(f"Starting TLS scan on {hostname}:{port}")
    context = ssl.create_default_context() 

    # disable port cert verification for self-signed test servers
    # in production this should always be True
    if port != 443:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("ALL:@SECLEVEL=0")

    with socket.create_connection((hostname, port), timeout=10) as sock: # opens raw TCP connection to target
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock: # takes raw TCP connection and wraps it in TLS; handshake
            protocol = tls_sock.version() # returns protocol version of what the connection agreed on
            cipher_info = tls_sock.cipher() # returns tuple of three; cipher suite name, protocol version, key length in bits
            cipher_name = cipher_info[0] if cipher_info else "UNKNOWN" 
            logger.info(f"Handshake complete - protocol: {protocol}, cipher: {cipher_name}")
            cert = tls_sock.getpeercert() # pulls the server's cert details as a Python dictionary

    subject, issuer = {}, {}
    for item in cert.get("subject", []): # type: ignore
        for key, value in item:
            subject[key] = value
    for item in cert.get("issuer", []): # type: ignore
        for key, value in item:
            issuer[key] = value
    expiry = cert.get("notAfter", "UNKNOWN") # type: ignore

    return {
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "cipher": cipher_name,
        "cert_subject": subject.get("commonName", "UNKNOWN"), # type: ignore
        "cert_issuer": issuer.get("organizationName", "UNKNOWN"), # type: ignore
        "cert_expiry": expiry,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

def evaluate_results(scan: dict) -> dict:
    """
    Evaluate scan results against known weak protocols and cipher suites.

    Checks the protocol version and cipher suite name from the scan
    against the WEAK_PROTOCOLS and WEAK_CIPHERS sets. Also checks
    whether the certificate has already expired.

    Args:
        scan: The dictionary returned by scan_host()

    Returns:
        A dictionary containing the evaluation findings with keys:
        - protocol_weak: True if the protocol version is considered insecure
        - cipher_weak: True if the cipher suite contains a weak keyword
        - cert_expired: True if the certificate expiry date has passed
        - issues: A list of human-readable issue descriptions
        - passed: True if no issues were found
    """
    issues = []
    logger.info(f"Evaluating results for {scan['hostname']}")

    protocol_weak = scan["protocol"] in WEAK_PROTOCOLS
    if protocol_weak:
        issues.append(f"Weak protocol detected: {scan['protocol']}")

    cipher_weak = any(weak in scan["cipher"] for weak in WEAK_CIPHERS)
    if cipher_weak:
        issues.append(f"Weak cipher detected: {scan['cipher']}")

    cert_expired = False
    if scan["cert_expiry"] != "UNKNOWN":
        expiry_date = datetime.datetime.strptime(
            scan["cert_expiry"], "%b %d %H:%M:%S %Y %Z"
        )
        if expiry_date < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
            cert_expired = True
            issues.append(f"Certificate expired on: {scan['cert_expiry']}")

    logger.info(f"Evaluation complete - passed: {len(issues) == 0}, issues: {len(issues)}")
    return {
        "protocol_weak": protocol_weak,
        "cipher_weak": cipher_weak,
        "cert_expired": cert_expired,
        "issues": issues,
        "passed": len(issues) == 0
    }

def save_report(scan: dict, evaluation: dict) -> None:
    """
    Save scan and evaluation results to JSON and CSV files.
    Combines the raw scan data and evaluation findings into a single 
    report and writes it to artifacts/release/ in both JSON and CSV
    format. Files are named using the hostname and a UTC timestamp
    so multiple scans of the same host never overwrite each other.

    Args:
        scan: The dictionary returned by scan_host()
        evaluation: The dictionary returned by evaluate_results()
    """
    report = {**scan, **evaluation} # merges two dictionaries as one dict

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_filename = f"{scan['hostname']}_{timestamp}"

    json_path = ARTIFACTS_DIR / f"{base_filename}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    csv_path = ARTIFACTS_DIR / f"{base_filename}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=report.keys())
        writer.writeheader()
        writer.writerow(report)

    print(f"Report saved to {json_path} and {csv_path}")

def main():
    """
    Entry point for the TLS Auditor scanner.

    Reads a hostname from the command line, runs a full scan and 
    evaluation, prints a summary to the terminal, and saves the
    report to artifacts/release/.

    Usage:
        python src/auditor.py <hostname>
    
    Example:
        python src/auditor.py google.com
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python src/auditor.py <hostname>")
        sys.exit(1)
    
    hostname = sys.argv[1].strip()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    # input validation
    if not hostname:
        print("Error: hostname cannot be empty.")
        sys.exit(1)

    if not (1 <= port <= 65535):
        print(f"Error: port {port} is out of valid range (1-65535).")
        sys.exit(1)

    logger.info(f"Input validated - hostname: {hostname}, port: {port}")

    print(f"\n--- TLS Auditor ---")
    print(f"Scanning: {hostname}\n")

    try:
        scan = scan_host(hostname, port)
        evaluation = evaluate_results(scan)
        save_report(scan, evaluation)

        print(f"Host:       {scan['hostname']}")
        print(f"Protocol:   {scan['protocol']}")
        print(f"Cipher:     {scan['cipher']}")
        print(f"Subject:    {scan['cert_subject']}")
        print(f"Issuer:     {scan['cert_issuer']}")
        print(f"Expiry:     {scan['cert_expiry']}")
        print(f"Timestamp:  {scan['timestamp']}")
        print()

        if evaluation["passed"]:
            print("Result: PASSED - no issues found.")
        else:
            print("Result: FAILED - issues detected:")
            for issue in evaluation["issues"]:
                print(f"    - {issue}")

    except Exception as e:
        print(f"Error scanning {hostname}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()