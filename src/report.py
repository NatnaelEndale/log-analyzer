from .analyzer import Analyzer
import json

class Report():
    def __init__(self, file_path):
        self.file = file_path
    def report(self):
        analyzer = Analyzer(self.file)
        ranked_ip = analyzer.rank_ip()
        for ip, rank in ranked_ip.items():
            if not ip and rank > 1:
                print("ALERT! There is a System Failer!")
            if rank > 2:
                print(f"ALERT! System is Under Attack! from ip: {ip}")
            elif ip and rank > 1.5:
                print(f"Keep an eye on this ip: {ip}")
    def summary(self):
        num_of_auth_event = 0
        num_of_web_events = 0
        num_of_system_event = 0
        num_of_succ_log = 0
        num_of_fail_log = 0
        num_of_system_error = 0
        num_of_high_risk = 0
        num_of_medium_risk = 0
        num_of_low_risk = 0

        with open(self.file, 'r') as f:
            for line in f:
                data_dict = json.loads(line)
                event_type = data_dict.get("event_type")
                risk = data_dict.get("risk")
                if event_type == "FAILED_LOGIN" or event_type == "SUCCESS_LOGIN":
                    num_of_auth_event += 1
                    if event_type == "FAILED_LOGIN":
                        num_of_fail_log += 1
                    elif event_type == "SUCCESS_LOGIN":
                        num_of_succ_log += 1
                elif event_type == "HTTP_REQUEST":
                    num_of_web_events += 1
                elif event_type == "SYSTEM_LOG" or event_type == "SYSTEM_ERROR":
                    num_of_system_event += 1
                    if event_type == "SYSTEM_ERROR":
                        num_of_system_error += 1
                
                if risk == "HIGH":
                    num_of_high_risk += 1
                elif risk == "MEDIUM":
                    num_of_medium_risk += 1
                elif risk == "LOW":
                    num_of_low_risk += 1
                else:
                    print("UNKNOWN: Unecpected!!!")

        print("========= LOG SUMMARY ==========")
        print(f"Total Events\n\n")

        print(f"Authentication Events: {num_of_auth_event}")
        print(f"Web Events: {num_of_web_events}")
        print(f"System Events: {num_of_system_event}\n\n")
        
        print("CATEGORIES OF AUTHENTICATION EVENTS")
        print(f"Successful Logins: {num_of_succ_log}")
        print(f"Failed Logins: {num_of_fail_log}\n\n")

        print(f"WEB AND SYSTEM FAILURES")
        print(f"HTTP Requests: {num_of_web_events}")
        print(f"System Errors: {num_of_system_error}\n\n")

        print("EVENTS CLASSIFIED BY THEIR RISK")
        print(f"High Risk Events: {num_of_high_risk}")
        print(f"Medium Risk Events: {num_of_medium_risk}")
        print(f"Low Risk Events: {num_of_low_risk}")


  

