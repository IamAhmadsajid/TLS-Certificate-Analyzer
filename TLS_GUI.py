import importlib.util
import subprocess
import sys
import time
import webbrowser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Function to check and install required modules
def check_requirements():
    required_modules = ['ssl', 'socket', 'cryptography', 'datetime', 'subprocess', 'webbrowser']
    missing_modules = [module for module in required_modules if importlib.util.find_spec(module) is None]

    if missing_modules:
        messagebox.showwarning("Missing Modules", "The following required modules are missing:\n" + "\n".join(missing_modules))
        install = messagebox.askyesno("Install Modules", "Do you want to install them?")
        if install:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_modules)
            messagebox.showinfo("Success", "Requirements installed successfully.")
            webbrowser.open("https://github.com/IamAhmadsajid")
        else:
            messagebox.showinfo("Cancelled", "Requirements installation cancelled.")
            sys.exit()
    else:
        print("All required modules are installed.")

check_requirements()

import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

# Step 1: Retrieve the TLS certificate from the server
def get_certificate(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version()
            der_cert = ssock.getpeercert(True)
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    return pem_cert, tls_version

# Step 2: Parse the PEM certificate
def parse_certificate(pem_data):
    cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
    return cert

# Step 3: Analyze the certificate details for simple scan
def analyze_certificate_simple(cert):
    details = {
        "Subject": cert.subject,
        "Issuer": cert.issuer,
        "Valid From": cert.not_valid_before_utc,
        "Valid To": cert.not_valid_after_utc,
        "Serial Number": cert.serial_number
    }
    return details

# Step 4: Analyze the certificate details for verbose scan including vulnerability scan
def analyze_certificate_verbose(cert):
    details = analyze_certificate_simple(cert)
    details["Extensions"] = parse_extensions(cert.extensions)
    weaknesses = []
    vulnerabilities = []
    current_time = datetime.now(timezone.utc)

    if cert.not_valid_after_utc < current_time:
        weaknesses.append("The certificate has expired.")

    # Check for weak cryptographic algorithms
    weak_algorithms = {'md5', 'sha1'}  # Example of weak cryptographic algorithms
    for extension in cert.extensions:
        if extension.oid.dotted_string == "2.5.29.15":
            if extension.value.digital_signature or extension.value.content_commitment:
                vulnerabilities.append("Weak cryptographic algorithm used: MD5 or SHA1")

    # Add more vulnerability checks as needed

    details["Weaknesses"] = weaknesses
    details["Vulnerabilities"] = vulnerabilities
    return details

# Helper function to parse and format extensions
# Helper function to parse and format extensions
def parse_extensions(extensions):
    parsed_extensions = []
    for extension in extensions:
        if extension.oid._name == "subjectAltName":
            alt_names = extension.value.get_values_for_type(x509.DNSName)
            parsed_extensions.append(f"Subject Alternative Names: {', '.join(alt_names)}")
        elif extension.oid._name == "basicConstraints":
            basic_constraints = "This is a CA certificate" if extension.value.ca else "This is not a CA certificate"
            parsed_extensions.append(f"Basic Constraints: {basic_constraints}")
        elif extension.oid._name == "keyUsage":
            key_usage = []
            if extension.value.digital_signature:
                key_usage.append("Digital Signature")
            if extension.value.content_commitment:
                key_usage.append("Content Commitment")
            if extension.value.key_encipherment:
                key_usage.append("Key Encipherment")
            if extension.value.data_encipherment:
                key_usage.append("Data Encipherment")
            if extension.value.key_agreement:
                key_usage.append("Key Agreement")
                if extension.value.encipher_only:
                    key_usage.append("Encipher Only")
                if extension.value.decipher_only:
                    key_usage.append("Decipher Only")
            if extension.value.key_cert_sign:
                key_usage.append("Certificate Signing")
            if extension.value.crl_sign:
                key_usage.append("CRL Signing")
            parsed_extensions.append(f"Key Usage: {', '.join(key_usage)}")
        elif extension.oid._name == "extendedKeyUsage":
            extended_key_usages = [usage._name for usage in extension.value]
            parsed_extensions.append(f"Extended Key Usage: {', '.join(extended_key_usages)}")
        elif extension.oid._name == "authorityKeyIdentifier":
            parsed_extensions.append("Authority Key Identifier: Present")
        elif extension.oid._name == "subjectKeyIdentifier":
            parsed_extensions.append("Subject Key Identifier: Present")
        elif extension.oid._name == "crlDistributionPoints":
            crl_points = [str(point.full_name[0].value) for point in extension.value]
            parsed_extensions.append(f"CRL Distribution Points: {', '.join(crl_points)}")
        else:
            parsed_extensions.append(f"{extension.oid._name}: {extension.value}")
    return parsed_extensions


# Helper function to format and print the verbose certificate details including vulnerabilities
def format_certificate_details_verbose(details, tls_version):
    output = []
    output.append("Simple Certificate Details:")
    output.append("---------------------------")
    output.append(f"Subject: {details['Subject']}")
    output.append(f"Issuer: {details['Issuer']}")
    output.append(f"Valid From: {details['Valid From']}")
    output.append(f"Valid To: {details['Valid To']}")
    output.append(f"Serial Number: {details['Serial Number']}")
    output.append(f"SSL/TLS Version: {tls_version}")
    output.append("\nVerbose Certificate Details:")
    output.append("----------------------------")
    output.append("Extensions:")
    for extension in details['Extensions']:
        output.append(f"  - {extension}")
    output.append("\nWeaknesses:")
    if details['Weaknesses']:
        for weakness in details['Weaknesses']:
            output.append(f"  - {weakness}")
    else:
        output.append("  - No weaknesses found.")
    output.append("\nVulnerabilities:")
    if details['Vulnerabilities']:
        for vulnerability in details['Vulnerabilities']:
            output.append(f"  - {vulnerability}")
    else:
        output.append("  - No vulnerabilities found.")
    return "\n".join(output)

def format_certificate_details_simple(details, tls_version):
    output = []
    output.append("Simple Certificate Details:")
    output.append("---------------------------")
    output.append(f"Subject: {details['Subject']}")
    output.append(f"Issuer: {details['Issuer']}")
    output.append(f"Valid From: {details['Valid From']}")
    output.append(f"Valid To: {details['Valid To']}")
    output.append(f"Serial Number: {details['Serial Number']}")
    output.append(f"SSL/TLS Version: {tls_version}")
    return "\n".join(output)

# Function to simulate scanning progress
def display_progress():
    progress_bar['value'] = 0
    for i in range(101):
        time.sleep(0.08)  # Simulate work by sleeping
        progress_bar['value'] = i
        root.update_idletasks()

# Main function to get user input and perform the analysis
def main():
    hostname = hostname_entry.get()
    scan_mode = scan_mode_var.get()

    try:
        display_progress()

        certificate_pem, tls_version = get_certificate(hostname)
        certificate = parse_certificate(certificate_pem)

        if scan_mode == 'simple':
            cert_details = analyze_certificate_simple(certificate)
            result = format_certificate_details_simple(cert_details, tls_version)
        elif scan_mode == 'verbose':
            cert_details = analyze_certificate_verbose(certificate)
            result = format_certificate_details_verbose(cert_details, tls_version)
        else:
            messagebox.showerror("Error", "Invalid scan mode selected. Please choose 'simple' or 'verbose'.")
            return

        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("TLS Certificate Scanner")
root.geometry("700x600")

# Create and place widgets
header_label = ttk.Label(root, text="TLS Certificate Scanner", font=("Helvetica", 16))
header_label.pack(pady=10)

hostname_label = ttk.Label(root, text="Hostname (domain name or IP address):")
hostname_label.pack(pady=5)
hostname_entry = ttk.Entry(root, width=50)
hostname_entry.pack(pady=5)

scan_mode_label = ttk.Label(root, text="Choose scan mode:")
scan_mode_label.pack(pady=5)
scan_mode_var = tk.StringVar(value="simple")
simple_radio = ttk.Radiobutton(root, text="Simple", variable=scan_mode_var, value="simple")
simple_radio.pack(anchor=tk.W, padx=20)
verbose_radio = ttk.Radiobutton(root, text="Verbose", variable=scan_mode_var, value="verbose")
verbose_radio.pack(anchor=tk.W, padx=20)

progress_bar = ttk.Progressbar(root, length=500, mode='determinate')
progress_bar.pack(pady=10)

scan_button = ttk.Button(root, text="Start Scan", command=main)
scan_button.pack(pady=10)

result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
result_text.pack(pady=10)

# Display the header
result_text.insert(tk.END, "\n======================================================================================\n")
result_text.insert(tk.END, "\tThis script is free to use. Owner isn't responsible for any misuse of the script.\n")
result_text.insert(tk.END, "\tThis script is available free on GitHub: \n")
result_text.insert(tk.END, "\tMade by Ahmad Sajid(https://github.com/IamAhmadsajid) and Faheem(021)\n")
result_text.insert(tk.END, "======================================================================================\n")

# Start the main event loop
root.mainloop()
