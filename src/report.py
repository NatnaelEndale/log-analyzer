from .analyzer import Analyzer
import json

class Report():
    def __init__(self, file_path):
        self.file = file_path
        self.result = {}
    def report(self):
        self.analyzer = Analyzer(self.file)
        ranked_ip = self.analyzer.rank_ip()
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
            num_of_events = 0
            for line in f:
                data_dict = json.loads(line)
                event_type = data_dict.get("event_type")
                risk = data_dict.get("risk")
                ip = data_dict.get("ip")
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

                if ip and ip in self.result:
                    self.result[ip][0] += 1
                    self.result[ip][1] = 0
                    self.result[ip][2].append(event_type)
                elif ip and ip not in self.result:
                    self.result[ip] = [1, 0, [event_type]]
                num_of_events += 1


        print("========= LOG SUMMARY ==========")
        print(f"{'Total Events:':<30} {num_of_events}\n\n")

        print(f"{'Authentication Events:':<30} {num_of_auth_event:<10}")
        print(f"{'Web Events:':<30} {num_of_web_events:<10}")
        print(f"{'System Events:':<30} {num_of_system_event:<10}\n\n")
        
        print("CATEGORIES OF AUTHENTICATION EVENTS")
        print(f"{'Successful Logins:':<30} {num_of_succ_log:<10}")
        print(f"{'Failed Logins:':<30} {num_of_fail_log:<10}\n\n")

        print(f"WEB AND SYSTEM FAILURES")
        print(f"{'HTTP Requests:':<30} {num_of_web_events:<10}")
        print(f"{'System Errors:':<30} {num_of_system_error:<10}\n\n")

        print("EVENTS CLASSIFIED BY THEIR RISK")
        print(f"{'High Risk Events:':<30} {num_of_high_risk:<10}")
        print(f"{'Medium Risk Events:':<30} {num_of_medium_risk:<10}")
        print(f"{'Low Risk Events:':<30} {num_of_low_risk:<10}\n\n")
 

    def top_susp_ips(self):
        suspicious_top = self.analyzer.top_suspicious()

        print("=========== TOP SUSPICIOUS IPS ===========")
        for row in suspicious_top:
            if row[0]:
                print(row[0])
                print(f"Events: {self.result[row[0]][0]}")
                print(f"Risk Score: {row[1]}")
                print(f"Reasons: {self.result[row[0]][2]}\n\n")

    def top_endpoints(self):
        end_point_result = {}
        with open(self.file, 'r') as f:
            for line in f:
                data_dict = json.loads(line)
                endpoint = data_dict.get("endpoint")
                if endpoint:
                    end_point_result[endpoint] = end_point_result.get(endpoint, 0) + 1

        print("============ TOP ENDPOINTS ==========")
        end_point_result = sorted(end_point_result.items(), key=lambda x: x[1], reverse=True)
        for tpl in end_point_result:
            print(f"{tpl[0]:<20} {tpl[1]}")


                
        
