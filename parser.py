import re

def string_parser(log_text):
    """
    Process the current log text and returns a structured dictionary with all relevant information

    Args:
        log_text (string): Raw log text storing information related to current log

    Return:
        dictionary: Structured dictionary holding all relevant informtion for future processing
    """

    # Initializes the dictionary and string for processing
    structured_text = {}
    tokens = log_text.split()

    # Initialized the string and hostname and adds it if found
    timestamp = re.search(r"[a-zA-Z]+ [0-9]+ [0-9]+\:[0-9]+\:[0-9]+", log_text)
    hostname = re.search(r"[a-zA-Z]+ [0-9]+ [0-9]+\:[0-9]+\:[0-9]+ ([A-Za-z0-9._-]+)", log_text)

    if timestamp and hostname:
        structured_text["Timestamp"] = timestamp.group(0)
        structured_text["Hostname"] = hostname.group(1)
    else:
        structured_text["Timestamp"] = "N/A"
        structured_text["Hostname"] = "N/A"

    # Checks and stores the log type and event type of current log text
    if "sshd" in log_text:
        if "session" in log_text:
            structured_text["Log Type"] = "sshd"
            structured_text["Event Type"] = "session"
        else:
            structured_text["Log Type"] = "sshd"
            structured_text["Event Type"] = "authentication"
    elif "sudo" in log_text:
        if "COMMAND=" in log_text:
            structured_text["Log Type"] = "sudo"
            structured_text["Event Type"] = "command"
        elif "incorrect password" in log_text or "authentication failure" in log_text:
            structured_text["Log Type"] = "sudo"
            structured_text["Event Type"] = "authentication"
        else:
            structured_text["Log Type"] = "sudo"
            structured_text["Event Type"] = "session"
    elif "CRON" in log_text:
        cron_session = re.search(r"\(cron\:session\)", log_text)
        if cron_session:
            structured_text["Log Type"] = "CRON"
            structured_text["Event Type"] = "session"
        else:
            structured_text["Log Type"] = "CRON"
            structured_text["Event Type"] = "task execution"
    else:
        structured_text["Log Type"] = "systemd"
        structured_text["Event Type"] = "service"
    
    # Checks and extracts relevant log information per raw log text
    for phrases in range(4, len(tokens)):
        if structured_text["Log Type"] == "systemd":
            pass
        if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "session":
            if tokens[phrases] == "session":
                structured_text["Action"] = tokens[phrases + 1]
            elif tokens[phrases] == "for":
                structured_text["Username"] = tokens[phrases + 2]
            elif tokens[phrases] == "by":
                structured_text["User"] = tokens[phrases + 1].split("(")[0]
            else:
                continue
        if structured_text["Event Type"] == "authentication" and structured_text["Log Type"] == "sshd":
            ip_address = re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", tokens[phrases])
            ssh_value = re.search(r"ssh[0-9]+", tokens[phrases])
            pid_phrase = re.search(r"sshd\[(\d+)\]", tokens[phrases])
            if ip_address:
                structured_text["IP"] = ip_address.group(0)
            if ssh_value:
                structured_text["Protocol"] = ssh_value.group(0)
            if pid_phrase:
                structured_text["PID"] = int(pid_phrase.group(1))
            if tokens[phrases] == "Failed":
                structured_text["Action"] = "Failed"
            elif tokens[phrases] == "Accepted":
                structured_text["Action"] = "Accepted"
            elif tokens[phrases] == "password":
                structured_text["Authentication Method"] = "password"
            elif tokens[phrases] == "publickey":
                structured_text["Authentication Method"] = "publickey"
            elif tokens[phrases] == "for":
                if tokens[phrases + 1] == "invalid":
                    structured_text["Username"] = tokens[phrases + 3]
                    structured_text["Invalid User"] = True
                else:
                    structured_text["Username"] = tokens[phrases + 1]
            elif tokens[phrases] == "port":
                structured_text["Port"] = int(tokens[phrases + 1])
            else:
                continue
        if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "authentication":
            sudo_user = re.search(r"sudo:\s*([a-zA-Z]+)\s*:", log_text)
            if "authentication failure" in log_text:
                structured_text["Action"] = "authentication failure"
            if "incorrect password attempts" in log_text:
                structured_text["Action"] = "incorrect password attempts"
            if sudo_user:
                structured_text["Username"] = sudo_user.group(1)
            if tokens[phrases].startswith("user="):
                structured_text["Username"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("uid="):
                structured_text["UID"] = int(tokens[phrases].split("=")[1])
            if tokens[phrases].startswith("euid="):
                structured_text["EUID"] = int(tokens[phrases].split("=")[1])
            if tokens[phrases].startswith("tty="):
                structured_text["TTY"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("ruser="):
                structured_text["RUSER"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("rhost="):
                structured_text["RHOST"] = tokens[phrases].split("=")[1]
            else:
                continue
        if structured_text["Log Type"] == "sshd" and structured_text["Event Type"] == "session":
            uid_token = re.search(r"uid=([0-9]+)", tokens[phrases])
            pid_phrase = re.search(r"sshd\[(\d+)\]", tokens[phrases])
            if uid_token:
                structured_text["UID"] = int(uid_token.group(1))
            if pid_phrase:
                structured_text["PID"] = int(pid_phrase.group(1))
            if tokens[phrases] == "session":
                structured_text["Action"] = tokens[phrases + 1]
            if tokens[phrases] == "for":
                structured_text["Username"] = tokens[phrases + 2]
        if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "command":
            sudo_user = re.search(r"sudo:\s*([a-zA-Z]+)\s*:", log_text)
            if sudo_user:
                structured_text["Username"] = sudo_user.group(1)
            if tokens[phrases].startswith("TTY="):
                structured_text["TTY"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("PWD="):
                structured_text["PWD"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("USER="):
                structured_text["USER"] = tokens[phrases].split("=")[1]
            if tokens[phrases].startswith("COMMAND="):
                structured_text["Action"] = tokens[phrases].split("=")[1]
        if structured_text["Log Type"] == "CRON" and structured_text["Event Type"] == "task execution":
            cron_pid_phrase = re.search(r"CRON\[(\d+)\]", tokens[phrases])
            cron_user = re.search(r"\(([a-zA-Z0-9_-]+)\)", tokens[phrases])
            if cron_pid_phrase:
                structured_text["PID"] = int(cron_pid_phrase.group(1))
            if cron_user:
                structured_text["Username"] = cron_user.group(1)
            if tokens[phrases] == "CMD":
                structured_text["COMMAND"] = log_text[log_text.index("CMD") + 3:len(log_text) - 1].replace(" (", "")
            else:
                continue
        if structured_text["Log Type"] == "CRON" and structured_text["Event Type"] == "session":
            cron_pid_phrase = re.search(r"CRON\[(\d+)\]", tokens[phrases])
            cron_uid_phrase = re.search(r"(uid=([0-9]+))", tokens[phrases])
            if cron_pid_phrase:
                structured_text["PID"] = int(cron_pid_phrase.group(1))
            if cron_uid_phrase:
                if cron_uid_phrase.group(2).isdigit():
                    structured_text["UID"] = int(cron_uid_phrase.group(2))
                else:
                    structured_text["UID"] = cron_uid_phrase.group(2)
            if tokens[phrases] == "session":
                structured_text["Action"] = tokens[phrases + 1]
            if tokens[phrases] == "for":
                structured_text["Username"] = tokens[phrases + 2]
            else:
                continue
        if structured_text["Log Type"] == "systemd" and structured_text["Event Type"] == "service":
            systemd_pid_phrase = re.search(r"systemd\[(\d+)\]", tokens[phrases])
            hostname_index = log_text.find(structured_text["Hostname"])
            action_phrase = re.search(r"[a-zA-z]\[[0-9]+\]\: ([a-zA-Z]+)", log_text)
            structured_text["Service"] = log_text[hostname_index + len(structured_text["Hostname"]) + 1:log_text.index("[")]
            if action_phrase:
                structured_text["Action"] = action_phrase.group(1)
            if systemd_pid_phrase:
                structured_text["PID"] = int(systemd_pid_phrase.group(1))
            if tokens[phrases] == structured_text["Action"]:
                structured_text["Description"] = log_text[action_phrase.end():]
    return structured_text