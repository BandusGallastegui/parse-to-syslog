import os
import tarfile
import wget
import re
from datetime import datetime

# Define the path to the project folder and the name of the folder to check
root_directory = 'extracted_files'
assumed_year = 2005

# Check if the folder exists
if not os.path.isdir(root_directory):
    # Step 1: Download the file
    url = "http://log-sharing.dreamhosters.com/hnet-hon-var-log-08302005.tar.bz2"
    filename = wget.download(url)

    # Step 2: Extract the tar.bz2 file
    extracted_dir = "extracted_files"
    os.makedirs(extracted_dir, exist_ok=True)

    with tarfile.open(filename, "r:bz2") as tar:
        tar.extractall(path=extracted_dir)

    # Step 3: Delete the original compressed file
    os.remove(filename)

class LogParser:
    def __init__(self, log_type, timestamp_regex='', hostname_regex='', app_name_regex='', procid_regex='', msgid_regex='', msg_regex=''):
        self.log_type = log_type
        self.timestamp_regex = timestamp_regex
        self.hostname_regex = hostname_regex
        self.app_name_regex = app_name_regex
        self.procid_regex = procid_regex
        self.msgid_regex = msgid_regex
        self.msg_regex = msg_regex
        
    def parse_log_line(self, log_line, prival=13):  # Default prival to 13 (user.notice)
        timestamp_match = re.search(self.timestamp_regex, log_line)
        hostname_match = re.search(self.hostname_regex, log_line)
        app_name_match = re.search(self.app_name_regex, log_line)
        procid_match = re.search(self.procid_regex, log_line) if self.procid_regex else None
        msgid_match = re.search(self.msgid_regex, log_line) if self.msgid_regex else None
        msg_match = re.search(self.msg_regex, log_line)
        
        timestamp_iso = None
        hostname = None
        app_name = None
        procid = None
        msgid = None
        msg = None
        structured_data = None

        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            # Convert timestamp to the desired format
            timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
            timestamp = timestamp.replace(year=assumed_year)
            timestamp_iso = timestamp.isoformat() + '.000Z'
        
        if hostname_match:
            hostname = hostname_match.group(1).lower()
        
        if app_name_match:
            app_name = app_name_match.group(1).lower()
        
        if procid_match:
            procid = procid_match.group(1).lower()
        
        if msgid_match and msgid_match.group(1):
            msgid = msgid_match.group(1).lower()
        
        if msg_match:
            msg = msg_match.group(1)
        
        # Construct the output string and replace empty variables with "-"
        log_string = f"<{prival}>{1} {timestamp_iso or '-'} {hostname or '-'} {app_name or '-'} {procid or '-'} {msgid or '-'} {structured_data or '-'} {msg or '-'}"
        
        return log_string

# Create a list of LogParser objects
log_parsers = [
    LogParser(
        log_type="boot.log",
        timestamp_regex=r'(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})',
        hostname_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} (\S+)',
        app_name_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ (\S+)(?=:)',
        procid_regex=r'',
        msgid_regex=r'',
        msg_regex=r': (.*)'
    ),
    LogParser(
        log_type="cron",
        timestamp_regex=r'(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})',
        hostname_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} (\S+)',
        app_name_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ (\S+)(?=\[)',
        procid_regex=r'\[(.*?)\]',
        msgid_regex=r'',
        msg_regex=r': (.*)'
    ),
    LogParser(
        log_type="messages",
        timestamp_regex=r'(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})',
        hostname_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} (\S+)',
        app_name_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ ([^\[:]+)',
        procid_regex=r'\[([^\]]+)\](?=:)',
        msgid_regex=r'',
        msg_regex=r': (.*)'
    ),
    LogParser(
        log_type="secure",
        timestamp_regex=r'(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})',
        hostname_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} (\S+)',
        app_name_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ ([^\[:]+)',
        procid_regex=r'\[([^\]]+)\](?=:)',
        msgid_regex=r'',
        msg_regex=r': (.*)'
    ),
    LogParser(
        log_type="tmplog",
        timestamp_regex=r'(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})',
        hostname_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} (\S+)',
        app_name_regex=r'\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S+ ([^\[:]+)',
        procid_regex=r'\[([^\]]+)\](?=:)',
        msgid_regex=r'',
        msg_regex=r': (.*)'
    )
]

# Create a dictionary to map logtype to LogParser objects
log_parsers_dict = {parser.log_type: parser for parser in log_parsers}

# Function to get a LogParser by its logtype
def get_log_parser_by_name(logtype_name):
    return log_parsers_dict.get(logtype_name, None)

def select_regex_pattern(file_path):
    # Normalize the file path for pattern matching
    relative_path = os.path.relpath(file_path, root_directory).replace(os.sep, '/')

    # Extract the path after 'var/log/'
    base_name = re.sub(r'\.\d+$', '', re.sub(r'^var/log/', '', relative_path))

    # Debug print to check the base name
    print(f"Base name: {base_name}")

    # Select and return the appropriate regex pattern if it exists
    selected_parser = get_log_parser_by_name(base_name)
    if selected_parser is None:
        raise ValueError(f"No parser found for log type: {base_name}")
    print(f"Selected parser: {selected_parser.log_type}")
    if selected_parser:
        return selected_parser
    else:
        raise ValueError(f"No pattern found for the file: {file_path}")

# Define mappings for facilities and severities
facility_map = {
    'kern': 0,
    'user': 1,
    'mail': 2,
    'daemon': 3,
    'auth': 4,
    'syslog': 5,
    'lpr': 6,
    'news': 7,
    'uucp': 8,
    'cron': 9,
    'local0': 16,
    'local1': 17,
    'local2': 18,
    'local3': 19,
    'local4': 20,
    'local5': 21,
    'local6': 22,
    'local7': 23,
}

severity_map = {
    'emergency': 0,
    'alert': 1,
    'critical': 2,
    'error': 3,
    'warning': 4,
    'notice': 5,
    'info': 6,
    'debug': 7,
}

# Define keywords for detection
keywords = {
    'authentication failure': {'facility': 'auth', 'severity': 'warning'},
    'failed login': {'facility': 'auth', 'severity': 'warning'},
    'invalid credentials': {'facility': 'auth', 'severity': 'warning'},
    'authentication success': {'facility': 'auth', 'severity': 'notice'},
    'login succeeded': {'facility': 'auth', 'severity': 'notice'},
    'disk full': {'facility': 'daemon', 'severity': 'critical'},
    'disk error': {'facility': 'daemon', 'severity': 'error'},
    'ALERT': {'facility': 'daemon', 'severity': 'alert'},
}

def parse_syslog_message(message):
    # Check for keywords in the message
    for keyword, properties in keywords.items():
        if keyword in message.lower():
            facility = facility_map[properties['facility']]
            severity = severity_map[properties['severity']]
            return keyword, facility, severity
    return None, None, None

parsed_logs = []

for root, dirs, files in os.walk(root_directory):
    for file in files:
        file_path = os.path.join(root, file)
        # Check if the file is empty (0KB)
        if os.path.getsize(file_path) == 0:
            print(f"Skipping empty file: {file_path}")
            continue

        try:
            selected_parser = select_regex_pattern(file_path)
            print(f"Selected parser: {selected_parser.log_type}")
        except ValueError as e:
            print(e)
            continue  # Skip this file if there is an error selecting the parser

        # Process the file
        try:
            with open(file_path, 'rb') as log_file:  # Open file in binary mode to read lines
                try:
                    lines = log_file.read().decode('utf-8')  # Decode the entire file
                except UnicodeDecodeError:
                    print(f"Skipping non-UTF-8 file: {file_path}")
                    continue

                for line in lines.splitlines():
                    try:
                        keyword, facility, severity = parse_syslog_message(line)
                        if keyword:
                            prival = (facility * 8) + severity
                        else:
                            prival = 13  # Default to user.notice if no keyword is found
                        rfc5424_log = selected_parser.parse_log_line(line, prival=prival)
                        parsed_logs.append(rfc5424_log)
                    except Exception as parse_error:
                        print(f"Error parsing line: {line}. Error: {parse_error}")
        except Exception as file_error:
            print(f"Error reading file: {file_path}. Error: {file_error}")

# Write parsed logs to a text file
output_file_path = "parsed_logs.log"
with open(output_file_path, 'w', encoding='utf-8') as output_file:
    for log in parsed_logs:
        output_file.write(str(log) + '\n')

print(f"Parsed logs have been written to {output_file_path}")
