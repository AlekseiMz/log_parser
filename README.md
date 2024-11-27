
# File IOC Processor

This script processes various types of files (CSV, PDF, JSON, HTML, and TXT) to extract Indicators of Compromise (IOCs), including MD5, SHA-1, SHA-256, SHA-512 hashes, IP addresses, domains, and URLs. The extracted IOCs are then saved to CSV and JSON files, providing a comprehensive report.

## Features

- **Supports multiple file formats**: PDF, CSV, JSON, HTML, TXT.
- **Extracts various types of IOCs**: MD5, SHA-1, SHA-256, SHA-512, IPv4, domain names, and URLs.
- **Validates IP addresses** to ensure they're public.
- **Validates domains** to ensure they are not just file extensions or common invalid domains.
- **Multithreaded file processing**: Uses `concurrent.futures` to process files in parallel for faster execution.

## Requirements

Before running the script, you need to set up your environment and install the necessary dependencies.

### Dependencies

- `pdfplumber`: For extracting text from PDF files.
- `ipaddress`: For handling and validating IP addresses.

### Python Version

Ensure you are using Python 3.6 or higher.

---

## Setup

### 1. Clone or Download the Repository

If you haven't already, clone or download this repository to your local machine.

```bash
git clone https://github.com/AlekseiMz/log_parser.git
cd log_parser
```

### 2. Install Dependencies
You can set up the environment using either the setup.sh (for Linux/macOS) or setup.bat (for Windows) scripts.

For Linux/macOS:

```bash
chmod +x setup.sh
./setup.sh
```

For Windows:

Simply double-click or run the following in Command Prompt:

```bash
setup.bat
```

This will:

Create a virtual environment (venv).
Install the required dependencies listed in requirements.txt.

## Usage

### 1. Prepare Your Input Files
Place the files you want to process in the same directory as the script or provide full paths. The script supports the following file types:

CSV
PDF
JSON
HTML
TXT


### 2. Run the Script
Run the script with the input files as arguments.

From the Command Line (Linux/macOS/Windows):

```bash
python3 log_parser.py <file1> <file2> ...
```

For example:

```bash
python3 log_parser.py file1.csv file2.pdf file3.json
```

This will process the files and output the results.


### 3. Output Files
CSV Report: A CSV file with all extracted IOCs will be saved in the output/ directory.
JSON Report: A JSON file with all IOCs in a structured format will also be saved in the output/ directory.

Example Output:

```bash
output/result.csv
output/result.json
```

### 4. Reviewing the IOC Report
After processing, you can review the IOCs found in the output files:

CSV: The CSV file will have the following columns:
filename: The name of the input file.
ioc_type: The type of IOC (e.g., md5, ipv4, domain).
value: The IOC value found.

JSON: The JSON file will contain a dictionary of IOCs categorized by type (e.g., md5, sha256, ipv4), with a list of unique values.

## Example Workflow
```
Clone/download the repository.
Run setup.sh or setup.bat to set up the environment.
Place your files (PDF, CSV, JSON, HTML, TXT) in the script directory.
Run the script to process the files and extract IOCs.
Review the output in the output/ directory.
```
