import requests
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup

# Define the URL to test
URL = "https://www.cyberforgesecurity.com"

# Date Variables
dated = datetime.now().strftime("%A, %B %d, %Y %I:%M:%S %p")
date_fdt = datetime.now().strftime("%Y%m%d%H%M%S")

# Function to test connectivity to a specific port
def test_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except Exception:
        return False

# Get HTTP response headers
response = requests.get(URL)
headers = response.headers

# Test common ports
ports = [21, 22, 53, 80, 443, 8080]
port_results = {port: test_port(URL.replace("https://", ""), port) for port in ports}

# Get SSL certificate information
hostname = URL.replace("https://", "")
cert_info = {}
try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cert_info = {
                "Host Name": hostname,
                "Issuer Name": cert.get('issuer', '')[-1][-1],
                "Effective Date": cert.get('notBefore'),
                "Expiration Date": cert.get('notAfter'),
            }
except Exception as e:
    cert_info = {"Error": str(e)}

# Fetch robots.txt, sitemap.xml, and crossdomain.xml
resources = {}
for path in ["/robots.txt", "/sitemap.xml", "/crossdomain.xml"]:
    try:
        res = requests.get(URL + path)
        resources[path] = res.text if res.status_code == 200 else f"Error: {res.status_code}"
    except Exception as e:
        resources[path] = f"Error: {str(e)}"

# Validate potentially vulnerable URLs
def validate_url(url):
    try:
        res = requests.get(url)
        return {
            "URL": url,
            "Status Code": res.status_code,
            "Reason": res.reason,
            "Message": res.text[:100] if res.status_code == 200 else "N/A",
        }
    except Exception as e:
        return {
            "URL": url,
            "Error": str(e),
        }

vulnerable_urls = [
    f"{URL}/wordpress/readme.html",
    f"{URL}/xmlrpc.php",
    f"{URL}/global.asa",
    f"{URL}/admin/createUser.php?member=myAdmin",
    f"{URL}/admin/changePw.php?member=myAdmin&passwd=foo123&confirm=foo123",
    f"{URL}/admin/groupEdit.php?group=Admins&member=myAdmin&action=add",
    f"{URL}/phpinfo.php",
]
validated_urls = [validate_url(url) for url in vulnerable_urls]

# Generate HTML report
html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>Python Webserver Security Report for {URL}</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f4f4f4; }}
        .open {{ color: green; font-weight: bold; }}
        .closed {{ color: red; font-weight: bold; }}
        .status-200 {{ color: green; font-weight: bold; }}
        .status-other {{ color: red; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Python Webserver Security Report</h1>
    <p><strong>Create By: Brad Voris</p>
    <p><strong>URL:</strong> {URL}</p>
    <p><strong>Executed:</strong> {dated}</p>

    <h2>Port Connectivity</h2>
    <table>
        <tr><th>Port</th><th>Status</th></tr>
        {''.join(f'<tr><td>{port}</td><td class={"open" if result else "closed"}>{"Open" if result else "Closed"}</td></tr>' for port, result in port_results.items())}
    </table>

    <h2>HTTP Response Headers</h2>
    <table>
        <tr><th>Header</th><th>Value</th></tr>
        {''.join(f'<tr><td>{key}</td><td>{value}</td></tr>' for key, value in headers.items())}
    </table>

    <h2>SSL Certificate Information</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        {''.join(f'<tr><td>{key}</td><td>{value}</td></tr>' for key, value in cert_info.items())}
    </table>

    <h2>Sitemaps, Robots, and Spider, XML</h2>
    <table>
        <tr><th>Resource</th><th>Content (Preview)</th></tr>
        {''.join(f'<tr><td>{path}</td><td>{content[:100]}...</td></tr>' for path, content in resources.items())}
    </table>

    <h2>Vulnerable URL Validation</h2>
    <table>
        <tr><th>URL</th><th>Status Code</th><th>Reason</th><th>Message</th></tr>
        {''.join(f'<tr><td>{result["URL"]}</td><td class={"status-200" if result.get("Status Code") == 200 else "status-other"}>{result.get("Status Code", result.get("Error"))}</td><td>{result.get("Reason", "")}</td><td>{result.get("Message", "")}</td></tr>' for result in validated_urls)}
    </table>
</body>
</html>"""

# Save the report to an HTML file
output_file = f"Webserver_Security_Report_{date_fdt}.html"
with open(output_file, "w") as file:
    file.write(html_report)

print(f"Report generated: {output_file}")
