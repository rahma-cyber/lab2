import ipaddress, time

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("192.168.56.0/24"),
]

def is_allowed(host):
    addr = ipaddress.ip_address(host)
    return any(addr in net for net in ALLOWED_NETWORKS)

def brute_sequential(host, port, username, wordlist, max_attempts=10):
    if not is_allowed(host):
        raise ValueError(f"Hôte {host} hors périmètre autorisé.")
    for password in wordlist[:max_attempts]:
        result = try_ssh_login(host, port, username, password)
        print(result)
        if result["outcome"] == "success":
            return result
        time.sleep(1)
    return None