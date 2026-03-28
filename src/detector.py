import re

INVALID_USER = 3
FAILED_LOGIN = 3
SYSTEM_ERROR = 2
HTTP_REQUEST = 1
SUCCESS_LOGIN = 0

RISK_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

class Detection:

    def __init__(self, parsed_in):
        self.parsed = parsed_in
        self.event_type = None
        self.risk = None
        self.priority = 0
        self.detected_log = {"ip": self.parsed.get("ip")}

    def update_event(self, new_event, new_priority):
        if new_priority >= self.priority:
            self.event_type = new_event
            self.priority = new_priority

    def update_risk(self, new_risk):
        if not self.risk or RISK_SCORE[new_risk] > RISK_SCORE[self.risk]:
            self.risk = new_risk

    def auth_process(self, auth):
        if "Failed password" in auth:
            self.update_event("FAILED_LOGIN", FAILED_LOGIN)
            self.update_risk("HIGH")

        elif "Accepted password" in auth:
            self.update_event("SUCCESS_LOGIN", SUCCESS_LOGIN)
            self.update_risk("LOW")

        if "invalid user" in auth:
            self.update_event("FAILED_LOGIN", INVALID_USER)
            self.update_risk("HIGH")
            self.detected_log["subtype"] = "INVALID_USER"


    def web_log_process(self, web_log):
        status = self.parsed.get("status")
        end_point = self.extract_endpoint(web_log)

        if "HTTP" in web_log:
            self.update_event("HTTP_REQUEST", HTTP_REQUEST)
        
        if status in ("401", "403") and end_point and "/admin" in end_point:
            self.update_risk("MEDIUM")

        else:
            self.update_risk("LOW")

        if status:
            self.detected_log["status_code"] = status
        if end_point:
            self.detected_log["endpoint"] = end_point
            

    def extract_endpoint(self, web_log):
        if web_log:
            match = re.search(r"(/[A-Za-z0-9/_-]+)", web_log)
            return match.group() if match else None
        return None

    def system_log_process(self, system_log):
        message = system_log
        if "Failed to start" in system_log:
            self.update_event("SYSTEM_ERROR", SYSTEM_ERROR)
            self.update_risk("HIGH")
        else:
            self.update_event("SYSTEM_LOG", 0)
            self.update_risk("HIGH")

        self.detected_log["message"] = message

    
    def process(self):
        authentication = self.parsed.get("login_event")
        web_log = self.parsed.get("web_request")
        system_log = self.parsed.get("system_event")

        if authentication:
            self.auth_process(authentication)

        if system_log:
            self.system_log_process(system_log)

        if web_log:
            self.web_log_process(web_log)

        self.detected_log["event_type"] = self.event_type or "UNKNOWN"
        self.detected_log["risk"] = self.risk or "LOW"

        return self.detected_log




