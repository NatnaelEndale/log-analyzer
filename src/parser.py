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
                    activity_record["web_request"] = web_request.group(1) # Here, I captured a bug, I wrote "system_event" instead of "web_request" in the previous version.

                system_log = re.search(r"(?<=systemd\[\d\]:\s).*", line)
                if system_log:
                    activity_record["system_event"] = system_log.group()

                time_stamp = re.search(r"(\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})", line)
                if time_stamp:
                    activity_record["time_stamp"] = time_stamp.group() or None

                self.activity_records_list.append(activity_record)
        return self.activity_records_list

