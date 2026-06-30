import re

def string_parser(log_text):
    structured_text=  {}
    tokens = log_text.split()

    timestamp = re.search(r"[a-zA-Z]+ [0-9]+ [0-9]+\:[0-9]+\:[0-9]+", log_text)
    hostname = re.search(r"[a-zA-Z]+ [0-9]+ [0-9]+\:[0-9]+\:[0-9]+ ([A-Za-z0-9._-]+)", log_text)

    if timestamp and hostname:
        structured_text["Timestamp"] = timestamp.group(0)
        structured_text["Hostname"] = hostname.group(1)
    else:
        structured_text["Timestamp"] = "N/A"
        structured_text["Hostname"] = "N/A"

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

    for phrases in range(4, len(tokens)):
        if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "session":
            if structured_text["Log Type"] == "sshd":
                if tokens[phrases] == "session":
                    structured_text["Action"] = tokens[phrases + 1]
                elif tokens[phrases] == "for":
                    structured_text["Username"] = tokens[phrases + 2]
                else:
                    continue
            elif structured_text["Log Type"] == "sudo":
                if tokens[phrases] == "session":
                    structured_text["Action"] = tokens[phrases + 1]
                elif tokens[phrases] == "for":
                    structured_text["Target User"] = tokens[phrases + 2]
                elif tokens[phrases] == "by":
                    structured_text["Invoking User"] = tokens[phrases + 1][:tokens[phrases + 1].index("(")]
                else:
                    continue
            else:
                pid_phrase = re.search(r"CRON\[(\d+)\]", tokens[phrases])
                if uid_token:
                    structured_text["UID"] = int(uid_token.group(2))
                if pid_phrase:
                    structured_text["PID"] = int(pid_phrase.group(1))
                if tokens[phrases] == "session":
                    structured_text["Action"] = tokens[phrases + 1]
                elif tokens[phrases] == "for":
                    structured_text["Target User"] = tokens[phrases + 2]
                else:
                    continue
        elif structured_text["Event Type"] == "authentication":
            ip_address = re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", tokens[phrases])
            ssh_value = re.search(r"ssh[0-9]+", tokens[phrases])
            pid_phrase = re.search(r"sshd\[(\d+)\]", tokens[phrases])
            if structured_text["Log Type"] == "sshd":
                if ip_address:
                    structured_text["IP Address"] = ip_address.group(0)
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
            else:
                uid_token = re.search(r"(uid=(\d+))", tokens[phrases])
                euid_token = re.search(r"(euid=(\d+))", tokens[phrases])
                if "authentication failure" in log_text:
                    structured_text["Action"] = "authentication failure"
                if "incorrect password attempts" in log_text:
                    structured_text["Action"] = "incorrect password attempts"
                if tokens[phrases].startswith("user="):
                    structured_text["Username"] = tokens[phrases][tokens[phrases].index("=") + 1:]
                if uid_token:
                    if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "authentication":
                        structured_text["UID"] = int(uid_token.group(2))
                if euid_token:
                    if structured_text["Log Type"] == "sudo" and structured_text["Event Type"] == "authentication":
                        structured_text["EUID"] = int(euid_token.group(2))
                if tokens[phrases].startswith("tty="):
                    structured_text["TTY"] = tokens[phrases].split("=")[1]
                if tokens[phrases].startswith("ruser="):
                    structured_text["RUSER"] = tokens[phrases].split("=")[1]
                if tokens[phrases].startswith("rhost="):
                    structured_text["RHOST"] = tokens[phrases].split("=")[1]
        elif structured_text["Event Type"] == "command":
            pass
        else:
            pass
    return structured_text

print(string_parser("May 31 09:31:10 ubuntu sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=lakshya rhost=  user=lakshya"))
print(string_parser("May 31 09:31:12 ubuntu sudo:     lakshya : 3 incorrect password attempts"))