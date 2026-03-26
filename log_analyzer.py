import re
import json


def parsing(file):
    activity_records_list = []
    with open(file) as f:
        for line in f:
            if line == "\n":
                continue
            ip = None
            activity_record = {}

            ip_object = re.search(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", line)
            if ip_object:
                ip = ip_object.group()
                activity_record["ip"] = ip

            auth_log = re.search(r"(\]:\s)(.+?)(?:\sfrom|\sport)", line)
            if auth_log:
                auth_log_txt = auth_log.group(2)
                activity_record["login_event"] = auth_log_txt

            status = re.search(r"(\d{3})$", line)
            if status:
                activity_record["status"] = status.group()

            web_request = re.search(r"(?<=\").*?(?=\")", line)
            if web_request:
                activity_record["web_request"] = web_request.group()

            system_log = re.search(r"(?<=systemd\[\d\]:\s).*", line)
            if system_log:
                activity_record["system_event"] = system_log.group()
                
            activity_records_list.append(activity_record)
    return activity_records_list

def detection(parsed):
    authentication = parsed.get("login_event")
    web_log = parsed.get("web_request")
    system_log = parsed.get("system_event")
    event_type = None
    risk = None
    ip = parsed.get("ip")
    detected_log = {"ip": ip}

    if authentication:
        if "Failed password" in authentication:
            event_type = "FAILED_LOGIN"
            risk = "MEDIUM"
        elif "Accepted password" in authentication:
            event_type = "SUCCESS_LOGIN"
            risk = "LOW"
        if "invalid user" in authentication:
            subtype = "INVALID_USER"
            risk = "HIGH"
            detected_log["subtype"] = subtype

    elif web_log:
        status = parsed.get("status")
        if "HTTP" in web_log:
            event_type = "HTTP_REQUEST"
            end_point = re.search(r"/\w+", web_log).group()
        if (status == "401" or status == "403") and end_point == "/admin":
            risk = "MEDIUM"
        else:
            risk = "LOW"
        if end_point:
            detected_log["endpoint"] = end_point
        if status:
            detected_log["status_code"] = status

    elif system_log:
        message = system_log
        if "Failed to start" in system_log:
            event_type = "SYSTEM_ERROR"
            risk = "HIGH"
        else:
            event_type = "SYSTEM_LOG"
            risk = "LOW"
        detected_log["message"] = message
     
    detected_log["event_type"] = event_type
    detected_log["risk"] = risk

    return detected_log

current_file = "auth_sample.log"

def store_to_json(current_file):    
    data_list = parsing(current_file)
    with open("log_analysis_report.json", "w") as f:
        for data in data_list:
            detected = detection(data)
            json.dump(detected, f)
            f.write("\n")
        print("The JSON file is written succefully!")


HIGH_RISK = 4
MEDIUM_RISK = 3
LOW_RISK = 1

json_file = "log_analysis_report.json"

def analyze_ip(file):
    ip_risk = {}
    ip_count = {}
    with open(file, "r") as f:
        for line in f:
            data_dict = json.loads(line)
            ip = data_dict.get("ip")
            risk = data_dict.get("risk")

            ip_count[ip] = ip_count.get(ip, 0)+1

            if risk == "HIGH":
                ip_risk[ip] = ip_risk.get(ip, 0) + HIGH_RISK
            elif risk == "MEDIUM":
                ip_risk[ip] = ip_risk.get(ip, 0) + MEDIUM_RISK
            elif risk == "LOW":
                ip_risk[ip] = ip_risk.get(ip, 0) + LOW_RISK
    return [ip_count, ip_risk]

data_to_analyze = analyze_ip(json_file)

def rank_ip(data_list):
    ranked_ip = {}
    for ip, r_rank in data_list[1].items():
        rank = r_rank / data_to_analyze[0][ip]
        ranked_ip[ip] = rank
    return ranked_ip

ranked_ip = rank_ip(data_to_analyze)

def report(ranked_ip):
    for ip, rank in ranked_ip.items():
        if not ip and rank > 1:
            print("ALERT! There is System Failer!")
        if rank > 2:
            print(f"ALERT!System is Under Attack! from ip: {ip}")
        elif ip and rank > 1.5:
            print(f"Keep an eye in this ip: {ip}")

report(ranked_ip)



     






