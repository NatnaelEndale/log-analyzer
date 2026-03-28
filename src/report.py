from .analyzer import Analyzer

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

