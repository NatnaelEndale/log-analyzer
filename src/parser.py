import re

class Parser():
    def __init__(self):
        self.activity_records_list = []
        self.ip = None

    def parsing(self, file):
        with open(file) as f:
            for line in f:
                if line == "\n":
                    continue
                activity_record = {}

                ip_object = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
                if ip_object:
                    self.ip = ip_object.group()
                    activity_record["ip"] = self.ip

                auth_log = re.search(r"(\]:\s)(.+?)(?:\sfrom|\sport)", line)
                if auth_log:
                    auth_log_txt = auth_log.group(2)
                    activity_record["login_event"] = auth_log_txt

                status = re.search(r"(\d{3})$", line)
                if status:
                    activity_record["status"] = status.group()

                web_request = re.search(r'"(.*?)"', line)
                if web_request:
                    activity_record["system_event"] = web_request.group()

                system_log = re.search(r"(?<=systemd\[\d\]:\s).*", line)
                if system_log:
                    activity_record["system_event"] = system_log.group()

                self.activity_records_list.append(activity_record)
        return self.activity_records_list



#file_path = "/home/natty/python-projects/myproject/log-analyzers/logs/auth_sample.log"

#parser_object = Parser()

#result_list = parser_object.parsing(file_path)

#print(result_list)








