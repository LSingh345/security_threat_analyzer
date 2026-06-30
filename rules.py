from datetime import datetime

# Stores the rules along with a dictionary/list holding the rule break occurences 
rules_dictionary = {"failed_logins_per_ip":{}, 
                    "Successful_logins_per_user":{}, 
                    "login_ips_per_user":{},
                    "sudo_activity_per_user":{},
                    "sudo_failures_per_user":{},
                    "session_activity_per_user":{},
                    "alert_history":[]}

def convert_timestamp(timestamp):
    """
    Converts the timestamp in the structured dictionary into a comparable format for brute force comparisons

    Args:
        timestamp (str): String that stores the timestamp of the current raw log text

    Return:
        str: A converted string which can be used for comparison
    """
    return datetime.strptime(timestamp, "%b %d %H:%M:%S")

def genereate_alert(alert, entity, message, details, timestamp):
    """
    Generates the alert when a rule break occurs

    Args:
        alert (str): Type of alert 
        entity (str): Entity it occured on
        message (str): Alert message
        details (str): Details of the alert message
        timestamp (str): Timestamp of the current raw log text

    Return:
        dict: A dictionary containing the details of the alert
    """

    # Initializes the alert and stores it in the alert history key
    alert_dict = {"type" : alert, 
                  "entity" : entity, 
                  "message" : message, 
                  "details" : details, 
                  "timestamp" : timestamp}
    rules_dictionary["alert_history"].append(alert_dict)
    return alert_dict

def update_failed_logins(event):
    """
    Stores the failed login attempts that occur from a certain IP address

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Stores time for failed IP login at the failed_logins_per_ip key
    if event["IP"] not in rules_dictionary["failed_logins_per_ip"]:
        rules_dictionary["failed_logins_per_ip"][event["IP"]] = []
        rules_dictionary["failed_logins_per_ip"][event["IP"]].append(event["Timestamp"])
    else:
        rules_dictionary["failed_logins_per_ip"][event["IP"]].append(event["Timestamp"])

def update_successful_logins(event):
    """
    Stores the successful logins from each username from the raw log text

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Stores time for successful IP login at the successful_logins_per_user key
    if (event["Username"] not in rules_dictionary["Successful_logins_per_user"]):
        rules_dictionary["Successful_logins_per_user"][event["Username"]] = []
        if (event["Action"] == "Accepted" and event["Authentication Method"] == "password") or (event["Action"] == "Accepted" and event["Authentication Method"] == "publickey"):
            rules_dictionary["Successful_logins_per_user"][event["Username"]].append(event["Timestamp"])
    else:
        if (event["Action"] == "Accepted" and event["Authentication Method"] == "password") or (event["Action"] == "Accepted" and event["Authentication Method"] == "publickey"):
            rules_dictionary["Successful_logins_per_user"][event["Username"]].append(event["Timestamp"])

def update_login_ips(event):
    """
    Stores the logins for each username per IP

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Stores the IP login for each username at the login_ips_per_user key
    if event["Username"] in rules_dictionary["login_ips_per_user"]:
        rules_dictionary["login_ips_per_user"][event["Username"]].append(event["IP"])
    else:
        rules_dictionary["login_ips_per_user"][event["Username"]] = []
        rules_dictionary["login_ips_per_user"][event["Username"]].append(event["IP"])

def update_sudo_activity(event):
    """
    Stores the number of sudo logins per username

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Increments successful sudo logins per username
    if event["Event Type"] == "authentication":
        if event["Username"] not in rules_dictionary["sudo_activity_per_user"]:
            rules_dictionary["sudo_activity_per_user"][event["Username"]] = 0
            if event["Action"] == "Accepted":
                rules_dictionary["sudo_activity_per_user"][event["Username"]] += 1
        else:
            if event["Action"] == "Accepted":
                rules_dictionary["sudo_activity_per_user"][event["Username"]] += 1

def update_sudo_failures(event):
    """
    Stores the number of sudo failures per username

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Increments failed sudo logins per username
    if event["Username"] not in rules_dictionary["sudo_failures_per_user"]:
        rules_dictionary["sudo_failures_per_user"][event["Username"]] = 0
        if event["Action"] == "Failed":
             rules_dictionary["sudo_failures_per_user"][event["Username"]] += 1
    else:
        if event["Action"] == "Failed":
            rules_dictionary["sudo_failures_per_user"][event["Username"]] += 1

def update_session_activity(event):
    """
    Stores the session action per each username

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
    """

    # Stores actions per username in the session_activity_per_user key
    if event["Username"] in rules_dictionary["session_activity_per_user"]:
        rules_dictionary["session_activity_per_user"][event["Username"]].append(event["Action"])
    else:
        rules_dictionary["session_activity_per_user"][event["Username"]] = []
        rules_dictionary["session_activity_per_user"][event["Username"]].append(event["Action"])

def check_brute_force(event, threshold = 5):
    """
    Checks to see if a brute force action occured by comparing 2 entries

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
        threshold (int): Holds the limit for the brute force detection

    Return:
        List: Stores whether a brute force occured or not 
    """

    # Initializes lists with failed logins and new list to hold the brute force detections
    old_list = rules_dictionary["failed_logins_per_ip"][event["IP"]][:]
    new_list = []

    # Converts the timestamp into a comparable format
    current_time = convert_timestamp(event["Timestamp"])

    # Detects and stores any brute force attempts
    for timestamps in old_list:
        old_time = convert_timestamp(timestamps)
        if (current_time - old_time).total_seconds() <= 300:
            new_list.append(timestamps)
    
    # Adds the occurences and checks to see if it crossed threshold
    new_list.append(event["Timestamp"])
    rules_dictionary["failed_logins_per_ip"][event["IP"]] = new_list
    if (len(new_list) >= threshold):
        return ["Brute Force Detected"]
    return []

def check_unusual_login_time(event, threshold = 3):
    """
    Checks to see if a user logeged in at a unusual time

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
        threshold (int): Holds the limit for the unusual login time

    Return:
        list: Holds the number of occurences for unusual login times
    """

    # Creates new list to compare against the standard login times
    flags_list = []
    user_login_hour = event["Timestamp"][7:9]

    # Compares and detects timestamps that occur at unusual times
    for times in  rules_dictionary["Successful_logins_per_user"][event["Username"]]:
        past_login_hour = event["Timestamp"][7:9]
        if abs(int(user_login_hour) - int(past_login_hour)) > threshold:
            flags_list.append("Abnormal Login Time")
    return flags_list

def check_new_login_ip(event):
    """
    Checks for logins that occur from suspicious IPs

    Args:
        event (dict): Structured dictionary holding the details of the current raw log

    Return:
        list: Holds the number of occurences of suspicious IP logins
    """

    # Creates new list to compare against the standard IP address 
    flags_list = []
    user_IP = event["IP"]

    # Checks and detects any suspicious IP logins
    if user_IP not in rules_dictionary["login_ips_per_user"][event["Username"]]:
        flags_list.append("This is a suspicious IP")
    return flags_list

def check_sudo_abuse(event, threshold = 4):
    """
    Checks for repeated sudo failures or suspicious sudo logins

    Args:
        event (dict): Structured dictionary holding the details of the current raw log
        threshold (int): Limit for repeated sudo failures

    Return:
        list: Holds the occurences of sudo failures 
    """

    # Creates list to store sudo failures
    flags_sudo_list = []

    # Compares and checks for suspicious sudo logins
    if event["Event Type"] == "authentication":
        if rules_dictionary["sudo_failures_per_user"][event["Username"]] > threshold:
            flags_sudo_list.append("Repeated Sudo Failures Detected")
    if event["Event Type"] == "command":
        dangerous_commands = ["passwd", "useradd", "usermod", "userdel", "/etc/passwd", 
                            "/etc/shadow", "/etc/sudoers", "systemctl stop", "systemctl disable", 
                            "systemctl restart ssh", "apt install", "apt remove", "apt purge", "dpkg -i", 
                            "chmod 777", "chmod /etc", "chown /etc", "rm -rf /", "rm -rf /etc", 
                            "rm -rf /var/log"]
        for commands in dangerous_commands:
            if commands in event["Action"]:
                flags_sudo_list.append("Suspicious Sudo Command")
                break

    return flags_sudo_list

def check_session_anomalies(event):
    """
    Checks to see if an anamoly is present

    Args:
        event (dict): Structured dictionary holding the details of the current raw log

    Return:
        list: Holds the occurences of anamoly detections
    """

    # Initializes checking for session anamolies
    actions = rules_dictionary["session_activity_per_user"][event["Username"]]
    flags = []
    toggles = 0

    # Checks and Detects for any session anamolies
    if actions[0] == "closed":
        flags.append("Anamoly has been detected")

    if actions.count("opened") == len(actions):
        flags.append("Anamoly has been detected")

    if actions.count("closed") == len(actions):
        flags.append("Anamoly has been detected")

    for i in range(1, len(actions)):
        if actions[i] == "closed" and actions[i-1] == "closed":
            flags.append("Anamoly has been detected")

        if actions[i] == "opened" and actions[i-1] == "opened":
            flags.append("Anamoly has been detected")

        if actions[i] != actions[i-1]:
            toggles += 1

    if toggles >= 3:
        flags.append("Anamoly has been detected")

    if actions[-1] == "opened":
        flags.append("Anamoly has been detected")

    return flags

def process_event(event):
    """
    Processes the passed dictionary and checks it against the rules present

    Args:
        event (dict): Structured dictionary holding the details of the current raw log

    Return:
        list: Holds the rule breaks that occured from the current log text
    """

    # Initializes list to store any detections or rule breaks
    flags = []

    # Checks structured dictionary and detect for any rule breaks
    if (event["Event Type"] == "session"):
        update_session_activity(event)
        output = check_session_anomalies(event)
        flags.extend(output)
    elif (event["Event Type"] == "authentication"):
        if event["Log Type"] == "sudo":
            update_sudo_failures(event)
            flags.extend(check_sudo_abuse(event))
        else:
            update_failed_logins(event)
            update_successful_logins(event)
            update_login_ips(event)
            flags.extend(check_brute_force(event))
            flags.extend(check_unusual_login_time(event))
            flags.extend(check_new_login_ip(event))
    elif (event["Event Type"] == "command"):
        update_sudo_activity(event)
        flags.extend(check_sudo_abuse(event))
    elif (event["Event Type"] == "task execution"):
        pass
    elif (event["Event Type"] == "service"):
        pass
    return flags