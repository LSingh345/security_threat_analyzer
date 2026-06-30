from datetime import datetime
import json

def aggregate_threats(threat_list, metadata):
    """
    Aggregates the threat list and attaches the metadata to produce the final JSON ready dictionary

    Args:
        threat_list (list): A list of threat flags returned from rules.py.
        metadata (dict): Metadata about the processed log file.

    Return:
        dict: A dictionary containing aggregated threat counts and metadata.
    """

    # Initializes the final JSON structure
    json_dictionary = {"threats":[], "metadata":metadata}
    threat_counter = {}

    # Counts the occurences of each threat flag
    for threat in threat_list:
        for flags in threat:
            if flags not in threat_counter:
                threat_counter[flags] = 1
            else:
                threat_counter[flags] += 1

    # Stores the aggregated threat counts
    json_dictionary["threats"] = threat_counter
    return json_dictionary


def generate_json_report(json_dictionary, output_file):
    """
    Generates the final JSON report and writes it to the disk

    Args:
        json_dictionary (dict): Contains aggregated threats and metadata
        output_file (json file): Path the JSON file is written
    """
    
    # Adds timestamp for when the report is generated
    date_str = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    json_dictionary["metadata"]["report_generated"] = date_str

    # Writes the JSON report to the output file
    json.dump(json_dictionary, output_file)