import os
import subprocess
import sys
import pandas as pd
import threading
import time
import logging
from queue import Queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import tempfile

# Define folder paths
OUTPUT_CSV_DIR = "./output_csv"
LOGS_DIR = "./logs"

# Create folders if they don't exist
os.makedirs(OUTPUT_CSV_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# File extensions to search
CERT_EXTENSIONS = (".jks", ".p12", ".pfx")

# Directories to exclude
IGNORE_DIRS = {".git", ".github", ".vscode", "node_modules", "build", "dist", "target", "out"}

# Generate timestamp for filenames
timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

# Thread-Safe Queue for Storing Results
results_queue = Queue()

# Lock to ensure safe access to shared resources
lock = threading.Lock()

# Counters for summary log
repos_with_jks = 0
repos_skipped_no_jks = 0
repos_failed_to_clone = 0

def setup_logging(org_name):
    """Setup logging with org name and timestamp in log filenames."""
    # Log files with org name and timestamp
    INFO_LOG_FILE = os.path.join(LOGS_DIR, f"scan_certificates_info_{org_name}_{timestamp_str}.log")
    ERROR_LOG_FILE = os.path.join(LOGS_DIR, f"scan_certificates_error_{org_name}_{timestamp_str}.log")
    SUMMARY_LOG_FILE = os.path.join(LOGS_DIR, f"summary_{org_name}_{timestamp_str}.log")

    # Clear any existing handlers
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Set the root logger level to DEBUG to capture all messages
    logger.setLevel(logging.DEBUG)

    # Info handler (for INFO and WARNING messages)
    info_handler = logging.FileHandler(INFO_LOG_FILE)
    info_handler.setLevel(logging.INFO)  # Capture INFO and above
    info_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    info_handler.setFormatter(info_formatter)
    logger.addHandler(info_handler)

    # Error handler (for ERROR messages)
    error_handler = logging.FileHandler(ERROR_LOG_FILE)
    error_handler.setLevel(logging.ERROR)  # Capture only ERROR messages
    error_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    error_handler.setFormatter(error_formatter)
    logger.addHandler(error_handler)

    return SUMMARY_LOG_FILE

def check_github_cli_authentication():
    """Check if GitHub CLI is authenticated."""
    try:
        # Log the full command being executed
        logging.info("Running command: gh auth status")

        result = subprocess.run(
            ["gh", "auth", "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        # Log the return code, stdout, and stderr
        logging.info(f"Command return code: {result.returncode}")
        logging.info(f"Command stdout: {result.stdout}")
        logging.info(f"Command stderr: {result.stderr}")

        # Check if the output contains any indication of being logged in
        if ("Logged in to github.com" in result.stdout or "✓ Logged in to github.com" in result.stdout or
            "Logged in to github.com" in result.stderr or "✓ Logged in to github.com" in result.stderr):
            logging.info("GitHub CLI is authenticated.")
            return True
        else:
            logging.error("GitHub CLI is not authenticated. Please run 'gh auth login'.")
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking GitHub CLI authentication: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error checking GitHub CLI authentication: {e}")
        return False

def clone_repository(repo_url, repo_path):
    """Clone a repository with retries and non-interactive mode."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Use --quiet to suppress prompts and make cloning non-interactive
            result = subprocess.run(
                ["gh", "repo", "clone", repo_url, repo_path, "--", "--quiet", "--depth=1"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                logging.info(f"Successfully cloned {repo_url} to {repo_path}")
                return True
            else:
                logging.warning(f"Attempt {attempt + 1} failed to clone {repo_url}: {result.stderr}")
                time.sleep(5)  # Wait before retrying
        except subprocess.TimeoutExpired:
            logging.warning(f"Attempt {attempt + 1} timed out while cloning {repo_url}")
            time.sleep(5)  # Wait before retrying
        except Exception as e:
            logging.error(f"Unexpected error cloning {repo_url}: {e}")
            return False

    logging.error(f"Failed to clone {repo_url} after {max_retries} attempts.")
    return False

def get_github_repos(org_name):
    """Fetch all repositories for an organization using GitHub CLI (gh) with pagination."""
    repos = []
    page = 1
    per_page = 100  # Maximum allowed per page

    while True:
        try:
            result = subprocess.run(
                [
                    "gh", "api",
                    f"orgs/{org_name}/repos?per_page={per_page}&page={page}",
                    "--jq", ".[].full_name"
                ],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                # Extract repository names
                page_repos = result.stdout.split("\n")
                if not page_repos or not page_repos[0]:  # No more repositories
                    break
                repos.extend([f"https://github.com/{repo}.git" for repo in page_repos if repo])
                page += 1
            else:
                logging.error(f"Failed to fetch repositories for {org_name}: {result.stderr}")
                break

        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing GitHub CLI for {org_name}: {e}")
            break

    return repos

def get_repo_contributors(repo_url):
    """Fetch list of contributors using GitHub CLI (gh)"""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo_url.split('https://github.com/')[-1].replace('.git', '')}/contributors", "--jq", ".[].login"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.split("\n")
        else:
            logging.error(f"Failed to fetch contributors for {repo_url}: {result.stderr}")
            return []
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing GitHub CLI for {repo_url}: {e}")
        return []

def find_certificate_files(repo_path):
    """Find JKS, P12, and PFX files inside a repository."""
    cert_files = []
    try:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                if file.endswith(CERT_EXTENSIONS):
                    cert_files.append(os.path.join(root, file))
    except Exception as e:
        logging.error(f"Error scanning repository {repo_path}: {e}")

    return cert_files

def extract_aliases(cert_file):
    """Extract alias names from JKS/P12/PFX files using keytool."""
    try:
        # First attempt: Try with the default password "changeit"
        result = subprocess.run(
            ["keytool", "-list", "-v", "-keystore", cert_file, "-storepass", "changeit"],
            capture_output=True, text=True, timeout=10, input="\n",
        )

        # If the command fails, try without -storepass and handle the password prompt
        if result.returncode != 0:
            logging.warning(f"Default password failed for {cert_file}. Attempting to prompt for password.")
            result = subprocess.run(
                ["keytool", "-list", "-v", "-keystore", cert_file],
                capture_output=True, text=True, timeout=10, input="\n\n",  # Simulate pressing Enter twice
            )

        # If the command still fails, log the error and return an empty list
        if result.returncode != 0:
            logging.error(f"Failed to extract aliases from {cert_file}: {result.stderr}")
            return []

        # Filter lines containing "Alias name"
        aliases = [line.split(":")[-1].strip() for line in result.stdout.split("\n") if "Alias name" in line]
        return aliases

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing keytool on {cert_file}: {e}")
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout while processing {cert_file}")
    except Exception as e:
        logging.error(f"Unexpected error processing {cert_file}: {e}")

    return []

def extract_valid_from(cert_file):
    """Extract 'Valid from' dates from JKS/P12/PFX files using keytool."""
    try:
        # First attempt: Try with the default password "changeit"
        result = subprocess.run(
            ["keytool", "-list", "-v", "-keystore", cert_file, "-storepass", "changeit"],
            capture_output=True, text=True, timeout=10, input="\n",
        )

        # If the command fails, try without -storepass and handle the password prompt
        if result.returncode != 0:
            logging.warning(f"Default password failed for {cert_file}. Attempting to prompt for password.")
            result = subprocess.run(
                ["keytool", "-list", "-v", "-keystore", cert_file],
                capture_output=True, text=True, timeout=10, input="\n\n",  # Simulate pressing Enter twice
            )

        # If the command still fails, log the error and return an empty list
        if result.returncode != 0:
            logging.error(f"Failed to extract valid-from dates from {cert_file}: {result.stderr}")
            return []

        # Extract 'Valid from' dates
        valid_from_metadata = []
        for line in result.stdout.split("\n"):
            if "Valid from" in line:
                valid_from_metadata.append(line.strip())

        return valid_from_metadata

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing keytool for valid-from extraction on {cert_file}: {e}")
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout while extracting valid from-date from {cert_file}")
    except Exception as e:
        logging.error(f"Unexpected error processing {cert_file}: {e}")

    return []

def check_expiry(valid_from_metadata):
    """Check if the certificate is expired based on the 'until' date."""
    today = datetime.now()
    for line in valid_from_metadata:
        if "until:" in line:
            expiry_date_str = line.split("until:")[-1].strip()
            try:
                expiry_date = datetime.strptime(expiry_date_str, "%a %b %d %H:%M:%S %Z %Y")
                if expiry_date < today:
                    return "Expired"
                else:
                    return "Active"
            except ValueError as e:
                logging.error(f"Error parsing expiry date: {e}")
                return "Unknown"
    return "Unknown"

def process_repository(repo_url, org_name, clone_dir):
    """Process each repository: clone, scan for certificates, extract aliases, and clean up."""
    global repos_with_jks, repos_skipped_no_jks, repos_failed_to_clone
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = os.path.join(clone_dir, repo_name)

    try:
        # Clone the repository
        logging.info(f"Cloning Repository {repo_name} from {org_name}")
        if not clone_repository(repo_url, repo_path):
            repos_failed_to_clone += 1
            return []

        # Check if the repository contains certificate files
        cert_files = find_certificate_files(repo_path)
        if not cert_files:
            logging.info(f"Skipping repository {repo_name} as it does not contain certificate files.")
            repos_skipped_no_jks += 1
            return []

        logging.info(f"Repository {repo_name} contains {len(cert_files)} certificate files. Proceeding with processing.")
        repos_with_jks += 1
        contributors = get_repo_contributors(repo_url)
        return [(cert_file, repo_name, org_name, contributors) for cert_file in cert_files]
    
    except Exception as e:
        logging.error(f"Error processing repository {repo_name}: {e}")
        repos_failed_to_clone += 1
        return []

def process_certificates_parallel(cert_files):
    """Process multiple certificate files in parallel"""
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_cert_alias = {executor.submit(extract_aliases, cert_file): cert_file for cert_file in cert_files}
        future_to_cert_valid = {executor.submit(extract_valid_from, cert_file): cert_file for cert_file in cert_files}

        aliases_results = {}
        valid_from_results = {}

        # Collect Alias results
        for future in as_completed(future_to_cert_alias):
            cert_file = future_to_cert_alias[future]
            try:
                aliases_results[cert_file] = future.result() or []
            except Exception as e:
                logging.error(f"Error extracting aliases from {cert_file}: {e}")
                aliases_results[cert_file] = []

        # Collect Valid-from results
        for future in as_completed(future_to_cert_valid):
            cert_file = future_to_cert_valid[future]
            try:
                valid_from_results[cert_file] = future.result() or []
            except Exception as e:
                logging.error(f"Error extracting valid-from from {cert_file}: {e}")
                valid_from_results[cert_file] = []

        # Store results in queue without ensuring list lengths
        for cert_file in cert_files:
            repo_name, org_name, contributors = cert_files[cert_file]
            aliases = aliases_results.get(cert_file, [])
            valid_from_dates = valid_from_results.get(cert_file, [])

            # Check expiry status
            expiry_status = check_expiry(valid_from_dates)

            # Directly pair available aliases with valid from dates
            for alias, valid_from in zip(aliases, valid_from_dates):
                with lock:
                    results_queue.put([alias, valid_from, cert_file, repo_name, org_name, contributors, expiry_status])

def save_results_to_csv(org_name):
    """Save results from queue to CSV"""
    data = []
    while not results_queue.empty():
        data.append(results_queue.get())

    # Include org name and timestamp in the CSV filename
    OUTPUT_CSV = os.path.join(OUTPUT_CSV_DIR, f"certificates_{org_name}_{timestamp_str}.csv")

    df = pd.DataFrame(data, columns=["Alias Name", "Valid From", "File Path", "Repository", "Organization", "Repo Owner", "Expiry"])
    df.to_csv(OUTPUT_CSV, index=False)
    logging.info(f"Results saved to {OUTPUT_CSV}")

def write_summary_log(summary_log_file):
    """Write summary log file"""
    with open(summary_log_file, "w") as f:
        f.write(f"Repositories with JKS files: {repos_with_jks}\n")
        f.write(f"Repositories skipped (no JKS files): {repos_skipped_no_jks}\n")
        f.write(f"Repositories failed to clone: {repos_failed_to_clone}\n")

def main(github_orgs):
    """Main execution function with multithreading"""
    # Setup logging for the first organization (logging is global, so it only needs to be done once)
    setup_logging(github_orgs[0])

    # Check GitHub CLI authentication before proceeding
    if not check_github_cli_authentication():
        logging.error("GitHub CLI authentication failed. Exiting.")
        return

    # Create a temporary directory for cloning repositories
    with tempfile.TemporaryDirectory() as clone_dir:
        logging.info(f"Using temporary directory for cloning: {clone_dir}")

        all_cert_files = {}

        with ThreadPoolExecutor(max_workers=5) as repo_executor:
            future_to_repo = {repo_executor.submit(process_repository, repo, org, clone_dir): (repo, org) for org in github_orgs for repo in get_github_repos(org)}

            for future in as_completed(future_to_repo):
                try:
                    cert_files = future.result()
                    for cert_file, repo_name, org_name, contributors in cert_files:
                        all_cert_files[cert_file] = (repo_name, org_name, contributors)

                except Exception as e:
                    logging.error(f"Error processing repository: {e}")

        # Process certificates in parallel
        process_certificates_parallel(all_cert_files)

        # Save final results to CSV
        for org in github_orgs:
            save_results_to_csv(org)

        # Write summary log
        for org in github_orgs:
            summary_log_file = os.path.join(LOGS_DIR, f"summary_{org}_{timestamp_str}.log")
            write_summary_log(summary_log_file)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan GitHub repositories for certificate files.")
    parser.add_argument("--orgs", nargs="+", required=True, help="GitHub organizations to scan")
    parser.add_argument("--background", action="store_true", help="Run in background mode")
    args = parser.parse_args()

    # Run the script as a background process if requested
    if args.background:
        if os.name == "posix":  # Unix-based systems
            subprocess.Popen(
                [sys.executable, __file__, "--orgs"] + args.orgs + ["--background"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        elif os.name == "nt":  # Windows
            subprocess.Popen(
                ["start", sys.executable, __file__, "--orgs"] + args.orgs + ["--background"],
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            print("Unsupported operating system. Running in the foreground.")
            main(args.orgs)
    else:
        # Run the script in the foreground
        main(args.orgs)
