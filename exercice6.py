def brute_with_backoff(host, port, username, wordlist, max_attempts=10):
    if not is_allowed(host):
        raise ValueError("Hôte non autorisé.")
    consecutive_errors = 0
    for password in wordlist[:max_attempts]:
        result = try_ssh_login(host, port, username, password)
        if result["outcome"] == "error":
            print(f"Erreur : {result.get('msg')}")
            consecutive_errors += 1
            if consecutive_errors >= 3:
                print("3 erreurs consécutives — verrouillage probable, attente 30s.")
                time.sleep(30)
                consecutive_errors = 0
            else:
                time.sleep(2)
        else:
            consecutive_errors = 0
            if result["outcome"] == "success":
                return result
        time.sleep(1)
    return None