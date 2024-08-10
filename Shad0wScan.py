import os
NUM_THREADS = min(100, os.cpu_count() * 4)
import socket
import requests
import re
import ssl
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Constants
NUM_THREADS = 100
SOCKET_TIMEOUT = 10
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}

open_ports = {}
scanned_ports = set()
cms_results = []

# Updated Service fingerprinting database
SERVICE_FINGERPRINTS = {
    "SSH-2.0-OpenSSH": "OpenSSH",
    "220 FTP": "FTP Server",
    "220": "Generic SMTP Server",
    "HTTP/1.1 200 OK": "Generic HTTP Server",
    "Nginx/1": "Nginx Web Server",
    "Apache/2": "Apache Web Server",
    "Microsoft-IIS/8": "Microsoft IIS Web Server",
    "vsFTPd": "vsFTPd Server",
    "220 ProFTPD": "ProFTPD FTP Server",
    "220 FileZilla Server": "FileZilla FTP Server",
}

# Updated CMS detection signatures
CMS_SIGNATURES = {
    "WordPress": {
        "url_paths": ["/wp-login.php", "/wp-admin/"],
        "headers": {"X-Pingback": "xmlrpc.php"},
        "content": [r"wp-content", r"wp-includes"],
    },
    "Joomla": {
        "url_paths": ["/administrator/", "/templates/system/css/system.css"],
        "content": [r"Joomla"],
    },
    "Drupal": {
        "url_paths": ["/user/login", "/core/misc/drupal.js"],
        "content": [r"Drupal.settings", r"Powered by Drupal"],
    },
    "Magento": {
        "url_paths": ["/admin/", "/js/mage/", "/skin/frontend/"],
        "content": [r"Mage.Cookies", r"Magento"],
    },
    "TYPO3": {
        "url_paths": ["/typo3/", "/typo3conf/"],
        "content": [r"TYPO3 CMS", r"typo3/"],
    },
    "Shopify": {
        "url_paths": [],
        "headers": {"X-Shopify-Stage": "production"},
        "content": [r"<!-- Shopify"],
    },
    "Squarespace": {
        "url_paths": ["/squarespace.json"],
        "headers": {},
        "content": [r"Squarespace.constants"],
    },
    "Wix": {
        "url_paths": ["/_api/wix-public-html-info-webapp/pages"],
        "headers": {},
        "content": [r"Wix.com Website Builder"],
    },
}

def display_message():
    print("""
"The Shad0ws betray you, because they belong to me"
                Developed by ./Shad0w
    """)

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))
        # Sending a complete HTTP GET request for HTTP/HTTPS services
        http_request = "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n".format(ip)
        sock.sendall(http_request.encode())
        banner = sock.recv(4096).decode('utf-8', 'ignore').strip()  # increased buffer size
        sock.close()
        return banner
    except Exception as e:
        return None

def fingerprint_service(banner):
    service_info = "Unknown Service"
    version_info = "Unknown Version"
    for fingerprint, service_name in SERVICE_FINGERPRINTS.items():
        if fingerprint in banner:
            service_info = service_name
            # Attempt to extract version information more aggressively
            pattern = re.compile(r'{} (\d+(\.\d+)*)'.format(re.escape(service_name)), re.IGNORECASE)
            match = pattern.search(banner)
            if match:
                version_info = match.group(1)
                break
    return service_info, version_info

def detect_cms(ip, port, verbose=False, retries=3):
    detected_cms = None
    url = f"http://{ip}:{port}"
    if port == 443:
        url = f"https://{ip}:{port}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    
    for attempt in range(retries):
        try:
            for cms, signature in CMS_SIGNATURES.items():
                # URL path check
                for path in signature.get("url_paths", []):
                    full_url = url + path
                    try:
                        response = requests.get(full_url, headers=headers, timeout=20, verify=False)
                        if response.status_code == 200:
                            detected_cms = cms
                            if verbose:
                                print(f"Detected CMS {cms} on {full_url}")
                            cms_results.append(f"CMS {cms} detected at {full_url}")
                            return cms, full_url
                    except requests.RequestException:
                        continue
                
                # Header check
                if not detected_cms:
                    for header, expected_value in signature.get("headers", {}).items():
                        if header in response.headers and expected_value in response.headers[header]:
                            detected_cms = cms
                            if verbose:
                                print(f"Detected CMS {cms} based on header {header}")
                            cms_results.append(f"CMS {cms} detected via header at {url}")
                            return cms, url
                
                # Content check
                if not detected_cms:
                    for pattern in signature.get("content", []):
                        if re.search(pattern, response.text, re.IGNORECASE):
                            detected_cms = cms
                            if verbose:
                                print(f"Detected CMS {cms} based on content pattern")
                            cms_results.append(f"CMS {cms} detected via content pattern at {url}")
                            return cms, url
            
            if not detected_cms and verbose:
                print(f"CMS detection failed on {url} (Attempt {attempt + 1}/{retries})")
        
        except Exception as e:
            if verbose:
                print(f"Error during CMS detection: {str(e)} (Attempt {attempt + 1}/{retries})")
    
    return None, None

def detect_service(ip, port, banner_grabbing=False, service_fingerprinting=False, verbose=False):
    service_name = COMMON_PORTS.get(port, "Unknown Service")
    version = "Unknown Version"
    banner = grab_banner(ip, port) if banner_grabbing and service_name != "Unknown Service" else None
    
    # Updated to handle version information based on the previous improvements
    if banner and service_fingerprinting:
        service_name, version = fingerprint_service(banner)  # Now returns both service and version
    elif banner:
        service_name += f" - {banner}"  # Keeps existing behavior if not fingerprinting

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        request_line = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"

        if service_name.startswith("HTTPS"):
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.sendall(request_line)
                response = ssock.recv(1024)
        else:
            sock.sendall(request_line)
            response = sock.recv(1024)

        if b"HTTP" in response:
            cms, cms_url = detect_cms(ip, port, verbose)
            if cms:
                service_name += f" ({cms}) - Version detected: {version}"
                if verbose:
                    print(f"CMS Detection Successful: {cms} detected at {cms_url}")
        sock.close()
        
    except Exception as e:
        service_name = "Unknown/Unresponsive"
        if verbose:
            print(f"Error detecting service on port {port}: {str(e)}")
    
    return f"{service_name} - Version: {version}"

def fingerprint_service(banner):
    if banner is None:
        return "Unknown Service", "Unknown Version"
    service_info = "Unknown Service"
    version_info = "Unknown Version"
    for fingerprint, service_name in SERVICE_FINGERPRINTS.items():
        if fingerprint in banner:
            service_info = service_name
            version_index = banner.find(service_name)
            version_details = banner[version_index:].split()
            if len(version_details) > 1:
                version_info = version_details[1]
            break
    return service_info, version_info

def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def scan_port(ip, port, banner_grabbing=False, service_fingerprinting=False, verbose=False):
    if port in scanned_ports:
        return
    scanned_ports.add(port)
    if check_port(ip, port):
        service = detect_service(ip, port, banner_grabbing, service_fingerprinting, verbose)
        print(f"Port {port} is open: {service}")
        open_ports[port] = service
    else:
        if verbose:
            print(f"Port {port} is closed after retries")

def worker(ip, ports, banner_grabbing=False, service_fingerprinting=False, verbose=False):
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(scan_port, ip, port, banner_grabbing, service_fingerprinting, verbose) for port in ports]
        for future in as_completed(futures):
            future.result()

def generate_output_report(ip, output_file):
    with open(output_file, 'w') as file:
        file.write(f"Scan report for {ip}\n")
        file.write(f"{len(open_ports)} open ports found:\n")
        for port, service in sorted(open_ports.items()):
            file.write(f"Port {port}: {service}\n")
        if cms_results:
            file.write("\nCMS Detection Results:\n")
            for result in cms_results:
                file.write(result + "\n")
        file.write("\nScan completed.\n")

def main():
    display_message()

    parser = argparse.ArgumentParser(description="Python PortScanner with additional Recon. - Developed by ./Shad0w")
    parser.add_argument("ip", help="The IP address or hostname to scan")
    parser.add_argument("-p", "--ports", help="The port range to scan (e.g., 1-1024)", default="1-1024")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-B", "--banner", help="Enable banner grabbing", action="store_true")
    parser.add_argument("-sF", "--service-fingerprinting", help="Enable service fingerprinting", action="store_true")
    parser.add_argument("-O", "--output", help="Output file to save the scan results", type=str)
    args = parser.parse_args()

    ip = args.ip
    port_range = args.ports
    verbose = args.verbose
    banner_grabbing = args.banner
    service_fingerprinting = args.service_fingerprinting
    output_file = args.output

    start_port, end_port = map(int, port_range.split('-'))
    ports = range(start_port, end_port + 1)

    worker(ip, ports, banner_grabbing, service_fingerprinting, verbose)

    print(f"\nScan report for {ip}")
    print(f"{len(open_ports)} open ports found:")
    for port, service in sorted(open_ports.items()):
        print(f"Port {port}: {service}")

    if cms_results:
        print("\nCMS Detection Results:")
        for result in cms_results:
            print(result)

    print("\nScan completed.")

    if output_file:
        generate_output_report(ip, output_file)
        print(f"Scan results saved to {output_file}")

if __name__ == "__main__":
    main()
