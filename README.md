# TLS Certificate Scanner

## Overview
TLS Certificate Scanner is a Python-based GUI tool designed to scan and analyze TLS/SSL certificates for a given hostname (domain name or IP address). The tool provides both simple and verbose scan modes, allowing users to get basic certificate details or a more in-depth analysis including potential weaknesses and vulnerabilities.

## Features
- Retrieve and parse TLS/SSL certificates from a given hostname.
- Provide basic certificate details such as Subject, Issuer, Validity period, and Serial Number.
- Conduct a verbose scan to analyze certificate extensions, weaknesses, and vulnerabilities.
- Display results in a user-friendly GUI built with Tkinter.
- Progress bar to indicate the scanning progress.
- Option to install any missing required Python modules.

## Requirements
- Python 3.6 or higher
- Required Python modules: `ssl`, `socket`, `cryptography`, `datetime`, `subprocess`, `webbrowser`

## Installation
Before running the script, make sure you have Python 3.6 or higher installed. The script will check for the required modules and prompt you to install any that are missing.

1. Clone the repository:
   ```sh
   git clone https://github.com/IamAhmadsajid/TLS-Certificate-Scanner.git
   ```
2. Navigate to the project directory:
   ```sh
   cd TLS-Certificate-Scanner
   ```
3. Install the required modules (if prompted by the script):
   ```sh
   python scanner.py
   ```

## Usage
1. Run the script:
   ```sh
   python scanner.py
   ```
2. Enter the hostname (domain name or IP address) you want to scan.
3. Select the scan mode (Simple or Verbose).
4. Click the "Start Scan" button.
5. View the scan results in the provided text area.

## GUI Components
- **Hostname Entry:** Input field for the user to enter the hostname.
- **Scan Mode Selection:** Radio buttons to choose between Simple and Verbose scan modes.
- **Progress Bar:** Indicates the progress of the scan.
- **Start Scan Button:** Initiates the scan process.
- **Result Display:** Scrolled text area to display the scan results.

## Example Output
### Simple Scan
```
Simple Certificate Details:
---------------------------
Subject: <Subject Details>
Issuer: <Issuer Details>
Valid From: <Start Date>
Valid To: <End Date>
Serial Number: <Serial Number>
SSL/TLS Version: <TLS Version>
```

### Verbose Scan
```
Simple Certificate Details:
---------------------------
Subject: <Subject Details>
Issuer: <Issuer Details>
Valid From: <Start Date>
Valid To: <End Date>
Serial Number: <Serial Number>
SSL/TLS Version: <TLS Version>

Verbose Certificate Details:
----------------------------
Extensions:
  - <Extension Details>

Weaknesses:
  - <Weakness Details>

Vulnerabilities:
  - <Vulnerability Details>
```

## License
This script is free to use. The owner is not responsible for any misuse of the script.

## Contributors
- Ahmad Sajid (https://github.com/IamAhmadsajid)
- Faheem (021)

## Disclaimer
This script is provided as-is without any warranty. Use it at your own risk. The owner is not responsible for any damage or loss caused by the use of this script.

## About the Project
This project is a semester project by students from Lahore Garrison University. Currently studying Bachelors of Science in Digital Forensics and Cyber Security, the project was developed as part of the learning process in Python during the course.

For more information and updates, visit the [GitHub repository](https://github.com/IamAhmadsajid/TLS-Certificate-Scanner).
