from parser import string_parser
from rules import process_event
from report import aggregate_threats, generate_json_report
from datetime import datetime
import argparse

"""
CLI Flags to implement
    --input <file>: allows the user to change the current input
    --output <file>: allows the user to change where the output will be stored
    --threshold <number>: allows the user to specify the threshold that controls how rule breaks are detected
"""

def parse_cli_flags():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=argparse.FileType("r"))
    parser.add_argument("--output", type=argparse.FileType("w"))
    parser.add_argument("--threshold", type=int)
    user_command = parser.parse_args()
    return user_command


def log_reader(args):
    """
    This function will read the log file, parse each line, applies rule-based threat detection,
    aggregate results, and generates a final JSON report

    Args:
        log_file (str): Path to the log file being analyzed

    Returns:
        dict: the final JSON report containing threats and metadata
    """

    # Open and read the log file line by line
    file_data = {}
    line_counter = 0
    log_results = []

    file = args.input
    
    for lines in file:
        output = lines.strip()

        #Converts the raw log text into a structured dictionary
        output_dict = string_parser(output)

        # Applies the rule checks to the parsed event
        rules_processing = process_event(output_dict)

        log_results.append(rules_processing)
        line_counter += 1

    # Stores the metadata for the processed file
    file_data["Total Lines"]  = line_counter
    file_data["Threats"] = sum(len(logs) for logs in log_results)
    file_data["Filename"]  = file.name
    file_data["Time Processed"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Aggregates the threats and generates the final JSON output
    final_log_results = aggregate_threats(log_results, file_data)
    final_report = generate_json_report(final_log_results, args.output)

    return final_report 
            
# Runs the tool on the sample log file
parse_object = parse_cli_flags()
log_reader(parse_object)