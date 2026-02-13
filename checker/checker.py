import copy
import os
import sys
import json
import string
import random
import requests

argv = copy.deepcopy(sys.argv)

OK, CORRUPT, MUMBLE, DOWN, CHECKER_ERROR = 101, 102, 103, 104, 110
SERVICENAME = "raccoonmili"
PORT = int(os.environ["PORT"]) if "PORT" in os.environ else 8080

requests.packages.urllib3.disable_warnings()

def rnd(n=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def close(code, public="", private=""):
    if public:
        print(public)
    if private:
        print(private, file=sys.stderr)
    print(f"Exit with code {code}", file=sys.stderr)
    sys.exit(code)

def url(ip: str, path: str) -> str:
    return f"http://{ip}:{PORT}{path}"

def req(method: str, ip: str, path: str, *, token=None, data=None, timeout=6):
    headers = {"User-Agent": "checker/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.request(method, url(ip, path), headers=headers, json=data, timeout=timeout, verify=False)
        return r
    except requests.exceptions.ConnectionError:
        close(DOWN, "Connection failed")
    except requests.exceptions.Timeout:
        close(DOWN, "Timeout")
    except Exception as e:
        close(MUMBLE, "HTTP error", str(e))

def info(*args):
    close(OK, "vulns: 1")

def init(*args):
    close(OK)

def check(*args):
    ip = args[0]

    r = req("GET", ip, "/health", timeout=4)
    if r.status_code != 200:
        close(DOWN, "Healthcheck failed")
    try:
        j = r.json()
        if not j.get("ok"):
            close(MUMBLE, "Bad health json")
    except Exception:
        close(MUMBLE, "Bad health response")

    u = "r" + rnd(10)
    p = rnd(18)
    title = "stash-" + rnd(6)
    content = "shine-" + rnd(24)

    r = req("POST", ip, "/api/register", data={"username": u, "password": p})
    if r.status_code not in (200, 409):
        close(MUMBLE, "Register unexpected code")

    r = req("POST", ip, "/api/login", data={"username": u, "password": p})
    if r.status_code != 200:
        close(MUMBLE, "Login failed")
    try:
        token = r.json()["token"]
    except Exception:
        close(MUMBLE, "Bad login json")

    r = req("POST", ip, "/api/stash", token=token, data={"title": title, "content": content})
    if r.status_code != 200:
        close(MUMBLE, "Create stash failed")

    r = req("GET", ip, "/api/stash", token=token)
    if r.status_code != 200:
        close(MUMBLE, "List stash failed")

    try:
        blob = json.dumps(r.json())
    except Exception:
        close(MUMBLE, "Bad stash json")

    if content not in blob:
        close(CORRUPT, "Newly created not found")

    close(OK)

def put(*args):
    ip, flag_id, flag = args[:3]

    u = "r" + rnd(10)
    p = rnd(18)
    title = "flag-" + rnd(6)

    r = req("POST", ip, "/api/register", data={"username": u, "password": p})
    if r.status_code not in (200, 409):
        close(MUMBLE, "Register failed")

    r = req("POST", ip, "/api/login", data={"username": u, "password": p})
    if r.status_code != 200:
        close(MUMBLE, "Login failed")
    try:
        token = r.json()["token"]
    except Exception:
        close(MUMBLE, "Bad login json")

    r = req("POST", ip, "/api/stash", token=token, data={"title": title, "content": flag})
    if r.status_code != 200:
        close(MUMBLE, "Create stash failed")

    r = req("GET", ip, "/api/stash", token=token)
    if r.status_code != 200:
        close(MUMBLE, "List stash failed")

    if flag not in json.dumps(r.json()):
        close(CORRUPT, "Flag not found right after put")

    close(OK, f"{u}:{p}")

def get(*args):
    ip, auth_data, flag = args[:3]
    if ":" not in auth_data:
        close(CHECKER_ERROR, private="Bad auth_data format")

    u, p = auth_data.split(":", 1)

    r = req("POST", ip, "/api/login", data={"username": u, "password": p})
    if r.status_code != 200:
        close(CORRUPT, "Login failed")
    try:
        token = r.json()["token"]
    except Exception:
        close(MUMBLE, "Bad login json")

    r = req("GET", ip, "/api/stash", token=token, timeout=7)
    if r.status_code != 200:
        close(MUMBLE, "List stash failed")

    try:
        blob = json.dumps(r.json())
    except Exception:
        close(MUMBLE, "Bad stash json")

    if flag not in blob:
        close(CORRUPT, "Flag not found")

    close(OK)

def error_arg(*args):
    close(CHECKER_ERROR, private=f"Wrong command {sys.argv[1]}")

COMMANDS = {
    "put": put,
    "check": check,
    "get": get,
    "info": info,
    "init": init,
}

if __name__ == "__main__":
    try:
        COMMANDS.get(argv[1], error_arg)(*argv[2:])
    except SystemExit:
        raise
    except Exception as ex:
        close(CHECKER_ERROR, private=f"INTERNAL ERROR: {ex}")
