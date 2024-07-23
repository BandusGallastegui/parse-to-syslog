import re
from datetime import datetime

def parse_syslog_line(line):
    # Regex to match RFC-5424 timestamp
    timestamp_pattern = re.compile(r'^\<\d+\>(\d{1}) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)')
    match = timestamp_pattern.match(line)
    if match:
        timestamp_str = match.group(2)
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        return timestamp, line
    else:
        # If the line does not match the pattern, return None for timestamp
        return None, line

def sort_syslog(input_file, output_file):
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    parsed_lines = [parse_syslog_line(line) for line in lines]
    
    # Filter out lines that did not match the timestamp pattern
    valid_lines = [line for line in parsed_lines if line[0] is not None]
    invalid_lines = [line[1] for line in parsed_lines if line[0] is None]
    
    # Sort lines by timestamp
    sorted_lines = sorted(valid_lines, key=lambda x: x[0])
    
    # Extract the original lines
    sorted_lines = [line[1] for line in sorted_lines]

    with open(output_file, 'w') as outfile:
        for line in sorted_lines + invalid_lines:
            outfile.write(line)

# Example usage with the provided log file
input_file = 'parsed_logs.log'
output_file = 'sorted_parsed_logs.log'
sort_syslog(input_file, output_file)
