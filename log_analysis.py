import csv
from collections import Counter, defaultdict
import re

# Configuration
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Regular expressions for parsing logs
LOG_PATTERN = r'(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - - \\[.*?\\] "\\w+ (?P<endpoint>/\\S*) HTTP/.*?" (?P<status>\\d+)'

# Function to parse the log file
def parse_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return [re.match(LOG_PATTERN, log).groupdict() for log in logs if re.match(LOG_PATTERN, log)]

# Function to analyze logs
def analyze_logs(parsed_logs):
    # Count requests per IP
    ip_request_count = Counter(log['ip'] for log in parsed_logs)

    # Identify the most frequently accessed endpoint
    endpoint_count = Counter(log['endpoint'] for log in parsed_logs)
    most_accessed_endpoint, endpoint_access_count = endpoint_count.most_common(1)[0]

    # Detect suspicious activity
    failed_logins = defaultdict(int)
    for log in parsed_logs:
        if log['status'] == '401':
            failed_logins[log['ip']] += 1

    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return ip_request_count, (most_accessed_endpoint, endpoint_access_count), suspicious_ips

# Function to save results to a CSV file
def save_to_csv(ip_request_count, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_count.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Empty row for separation

        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Empty row for separation

        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main execution
def main():
    # Parse logs
    parsed_logs = parse_logs(LOG_FILE)

    # Analyze logs
    ip_request_count, most_accessed, suspicious_ips = analyze_logs(parsed_logs)

    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_request_count.items():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_request_count, most_accessed, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
