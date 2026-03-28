import json

HIGH_RISK = 4
MEDIUM_RISK = 3
LOW_RISK = 1

class Analyzer():
    def __init__(self, json_file):
        self.file = json_file
        self.ip_risk = {}
        self.ip_count = {}
        self.ranked_ip = {}

    def analyze_ip(self):
        with open(self.file, "r") as f:
            for line in f:
                data_dict = json.loads(line)
                ip = data_dict.get("ip")
                risk = data_dict.get("risk")

                self.ip_count[ip] = self.ip_count.get(ip, 0) + 1

                if risk == "HIGH":
                    self.ip_risk[ip] = self.ip_risk.get(ip, 0) + HIGH_RISK
                elif risk == "MEDIUM":
                    self.ip_risk[ip] = self.ip_risk.get(ip, 0) + MEDIUM_RISK
                elif risk == "LOW":
                    self.ip_risk[ip] = self.ip_risk.get(ip, 0) + LOW_RISK
            return [self.ip_count, self.ip_risk]

    def rank_ip(self):
        ip_count, ip_risk= self.analyze_ip()
        for ip, r_rank in ip_risk.items():
            rank = r_rank / ip_count[ip]
            self.ranked_ip[ip] = rank
        return self.ranked_ip

