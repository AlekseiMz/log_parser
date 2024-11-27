import json
import csv
import pdfplumber
import re
import sys
import os
import mimetypes
import logging
import concurrent.futures
import ipaddress

# Configure logging to output messages with time, level, and message
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Define regex patterns for various Indicator of Compromise (IOC) types
IOC_PATTERNS = {
    "md5": re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])"),
    "sha1": re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])"),
    "sha256": re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])"),
    "sha512": re.compile(r"[0-9a-f]{128}"),
    "ipv4": re.compile(r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})"
                       r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})){3}\b"),
    "domain": re.compile(r"(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}"),
    "url": re.compile(r"https?://(?:[A-Za-z0-9\-]+\.)+[A-Za-z0-9]{2,}(?::\d{1,5})?[/A-Za-z0-9\-%?=\+\.]+")
}

# Set of supported file MIME types
SUPPORTED_TYPES = {"pdf", "csv", "html", "json", "txt"}

# Initialize list to hold valid input files
input_files = sys.argv[1:]
valid_files = []

# Validate input files
logging.info(f"Processing {len(input_files)} files...")
for file_path in input_files:
    resolved_path = os.path.realpath(file_path)
    if os.path.exists(resolved_path) and resolved_path.startswith(os.getcwd()):
        valid_files.append(resolved_path)
    else:
        logging.error(f"Invalid or non-existent file: {file_path}")

# Exit if no valid files
if not valid_files:
    logging.error("No valid files provided. Exiting script.")
    sys.exit(1)

# Map files to their MIME types
file_type_map = {}
for file in valid_files:
    mime_type, _ = mimetypes.guess_type(file)
    file_extension = mime_type.split("/")[-1] if mime_type else os.path.splitext(file)[1].lstrip('.')

    if file_extension in SUPPORTED_TYPES:
        file_type_map[file] = file_extension
    else:
        logging.warning(f"Trying {file} as plaintext.")
        file_type_map[file] = file_extension

# Define functions to extract text from various file types
def extract_pdf_text(pdf_path: str) -> str:
    """Extracts text from a PDF file."""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            return " ".join(page.extract_text() or "" for page in pdf.pages)
    except Exception as error:
        logging.error(f"Error reading PDF {pdf_path}: {error}")
        return ""

def process_file(file_name: str, mime_type: str) -> str:
    """Process a file and extract its content based on its MIME type."""
    try:
        if mime_type == "pdf":
            return extract_pdf_text(file_name)
        elif mime_type == "csv":
            with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
                return " ".join(" ".join(row) for row in csv.reader(file))
        elif mime_type in ["html", "txt"]:
            with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
                return file.read()
        elif mime_type == "json":
            with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
                return json.dumps(json.load(file), indent=2)
        elif mime_type == "plain":
            with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
                return file.read()
        else:
            logging.warning(f"Unsupported file type: {mime_type}")
            return ""
    except Exception as error:
        logging.error(f"Error reading {file_name}: {error}")
        return ""

# Parallelize file processing using ThreadPoolExecutor
file_contents = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    future_to_file = {executor.submit(process_file, file, mime): file for file, mime in file_type_map.items()}
    for future in concurrent.futures.as_completed(future_to_file):
        file = future_to_file[future]
        try:
            content = future.result().strip()
            if content:
                file_contents[file] = content.lower()  # Normalize content to lowercase
            else:
                logging.warning(f"File {file} is empty. Skipping.")
        except Exception as e:
            logging.error(f"Error processing file {file}: {e}")

# Cache for public IP checks to avoid redundant IP checks
ip_cache = {}

def is_public_ip(ip: str) -> bool:
    """Checks if an IP address is public, using a cache to avoid repeated checks."""
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        result = ipaddress.ip_address(ip).is_global
        ip_cache[ip] = result
        return result
    except ValueError:
        ip_cache[ip] = False
        return False

def is_valid_domain(domain: str) -> bool:
    """Checks if a domain is valid (excludes file extensions and common invalid domains)."""
    excluded_extensions = {".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".wav", ".mp4", ".avi", ".mov", ".zip", ".rar", ".html", ".css", ".js", ".json", ".exe", ".dll", ".jpg", ".png", ".gif", ".bmp", ".tiff", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".xml", ".html", ".css", ".js", ".json", ".zip", ".rar", ".tar", ".gz", ".7z", ".iso", ".mp3", ".wav", ".ogg", ".flac", ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".apk", ".exe", ".dll", ".bat", ".sh", ".psd", ".ai", ".php"}
    if any(domain.endswith(ext) for ext in excluded_extensions):
        return False
    # Simplified regex for valid domain check
    return bool(re.match(r"^(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!localhost)([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$", domain))

# Deduplicate and categorize IOCs across all files
ioc_results = {}
for file_name, content in file_contents.items():
    ioc_results[file_name] = {
        "ipv4": list(set(ip for ip in IOC_PATTERNS["ipv4"].findall(content) if is_public_ip(ip))),
        "domain": list(set(domain for domain in IOC_PATTERNS["domain"].findall(content) if is_valid_domain(domain)))
    }
    for ioc_type in {"md5", "sha1", "sha256", "sha512", "url"}:
        ioc_results[file_name][ioc_type] = list(set(IOC_PATTERNS[ioc_type].findall(content)))

# Consolidate IOCs from all files
all_iocs = {
    ioc_type: list(set(ioc for file_iocs in ioc_results.values() for ioc in file_iocs[ioc_type]))
    for ioc_type in IOC_PATTERNS.keys()
}

# Helper function to generate a unique filename for saving results
def generate_unique_filename(base_name: str, extension: str, output_dir: str = ".") -> str:
    counter = 1
    unique_name = os.path.join(output_dir, f"{base_name}{extension}")
    while os.path.exists(unique_name):
        unique_name = os.path.join(output_dir, f"{base_name}_{counter}{extension}")
        counter += 1
    return unique_name

# Set output directory and file paths
output_dir = "output"
os.makedirs(output_dir, exist_ok=True)

CSV_RESULTS_PATH = generate_unique_filename("result", ".csv", output_dir)
JSON_RESULTS_PATH = generate_unique_filename("result", ".json", output_dir)

# Export IOC results to CSV
def export_to_csv():
    """Exports the IOC results to a CSV file."""
    if not ioc_results:
        logging.info("No IOCs to export.")
        return
    try:
        with open(CSV_RESULTS_PATH, "w", newline='') as file:
            writer = csv.writer(file, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["filename", "ioc_type", "value"])
            for file_name, ioc_types in ioc_results.items():
                for ioc_type, iocs in ioc_types.items():
                    for ioc in iocs:
                        writer.writerow([file_name, ioc_type, ioc])
        logging.info(f"CSV results written to {CSV_RESULTS_PATH}")
    except Exception as e:
        logging.error(f"Error writing CSV: {e}")

# Export IOC results to JSON
def export_to_json():
    """Exports the IOC results to a JSON file."""
    if not all_iocs:
        logging.info("No IOCs to export.")
        return
    try:
        with open(JSON_RESULTS_PATH, "w") as file:
            json.dump(all_iocs, file, indent=4)
        logging.info(f"JSON results written to {JSON_RESULTS_PATH}")
    except Exception as e:
        logging.error(f"Error writing JSON: {e}")

# Generate IOC count report
def report_ioc_counts():
    """Generates a report of the number of IOCs found for each type."""
    if not all_iocs:
        logging.info("No IOCs to report.")
        return
    total_counts = {ioc_type: len(iocs) for ioc_type, iocs in all_iocs.items()}
    logging.info("IOC Counts Report:")
    for ioc_type, count in total_counts.items():
        logging.info(f"{ioc_type}: {count} instances found")

# Execute the reporting and exporting tasks
report_ioc_counts()
export_to_json()
export_to_csv()
