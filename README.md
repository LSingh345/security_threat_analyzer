Project Overview
	This project automates the log analysis process by reading raw log text, parsing each entry into a structured dictionary, applying security rules to detect suspicious behavior, and generating a JSON report	summarizing the threats and file metadata. Within organizations, logs are produced to track authentication activity, system usage, and potential security risks—but manually reviewing them is slow and error‑prone. This tool streamlines that process by automatically identifying anomalies such as brute‑force attempts, unusual login times, and suspicious IP addresses. As a result, companies can maintain stronger security visibility and respond to potential attacks in a fast and reliable way.

Features
	Log Parsing = Converts raw log text into structured dictionaries through extracting fields including timestamp, IP, username, and event type
	Threat Detection = Uses rule based checks in identifying suspicious and abnormal behavior
	Brute Force Detection = Flags repeated login attempts that occur within a short time window
	Unusual log time detection = Identifies logins that occur at abnormal hours compared to a user’s typical behavior 
	Suspicious IP Detection = Detects logins that occur from new or unexpected IP addresses
	Sudo Abuse Detection = Flags dangerous sudo commands or repeated sudo authentication failures 
	Session Anomaly Detection = Identifies irregular session patterns like mismatched open/close sequences
	JSON report generation = Produces a structured report which summarizes all the detected threats and file metadata 

Architecture
	main.py = Responsible for the entire operation of the project by reading the log files, parsing them into structured dictionaries, apply rule checks, and generate a final json report
	parser.py = Parses all the raw log text from the samplelog.txt file and converts each into a structured dictionary by extracting fields like timestamp, hostname, IP, username, log type, and event type 
	report.py = Generates the threat report by aggregating the detected threats along with combining the file metadata to a JSON file
	rules.py = Applies rule based threat detection using the log data and returns any flagged suspicious behavior
	samplelog.txt = Contains all the raw log data used for testing
	threat_report.json = JSON report that contains the detected threats along with the file metadata

How it works
	The program will read the log file which the user will provide and it will be read in the main.py file
	When reading, the tool will parse each raw log text into a structured dictionary where it will extract fields like timestamps, hostname, IP address, username, log type, and event type
	Each converted dictionary is passed to rules.py, where it is checked against a set of rule checks
	All of these flagged threats will be counted and combined with the metadata like total lines processed, number of threats, and the current processing time
	Lastly, a final JSON report will be generated where all the aggregated threats and file metadata are written to a JSON file summarizing all the findings

Sample Input + Output
	Input
		May 31 09:12:44 ubuntu sshd[1023]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
		May 31 09:12:47 ubuntu sshd[1023]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
		May 31 09:12:50 ubuntu sshd[1023]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
		May 31 09:13:10 ubuntu sshd[1101]: Accepted password for lakshya from 10.0.0.12 port 60211 ssh2
		May 31 09:13:10 ubuntu sshd[1101]: pam_unix(sshd:session): session opened for user lakshya by (uid=0)
	Output
		{"threats": {"Brute Force Detected": 1,"Anomaly has been detected": 2}, "metadata": {"Total Lines": 5, "Threats": 3, "Filename": "samplelog.txt", "Time Processed": "2026-06-26 17:12:13", "report_generated": "2026-06-26 17:12:13"}}

How to run
	To run the tool using CLI flags: python main.py --input samplelog.txt --output threat_report.json --threshold 5

Requirements
	Python 3.8+

Project Structure
├── main.py
├── parser.py
├── rules.py
├── report.py
├── samplelog.txt
├── threat_report.json
└── README.md

Future Improvements
	Expand CLI flags = Add more options like verbosity, stats-only mode, or custom rule files 
	Introduce a Config File = Move thresholds and rule settings into a JSON/YAML config to allow for easier tuning 
	Generate an HTML report = Produce a human readable visual report alongside the JSON report
	Add more detection rules = Expand the current rules to be able to detect privilege escalation, lateral movement, and repeated sudo failures
	Support multiple log formats = Extend the current parsing logic to be able to handle Apache logs, auth logs, or custom formats
	Add Unit tests = Help to improve the readability and maintainability with the automated test coverage
