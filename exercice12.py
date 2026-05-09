import time

def print_summary(stats):
    print(f"""

Hôte : {stats['host']}
Essais : {stats['attempts']}
Durée : {stats['duration']:.2f} sec
Moyenne : {stats['rate']:.2f} tentatives/sec
Résultat : {stats['result']}
Banner SSH : {stats.get('banner', 'Non disponible')}
Garde-fous :
- IP locales uniquement
- max 10 mots de passe
- pauses entre tentatives
- backoff en cas d'erreurs

""")

if __name__ == "__main__":
    start = time.time()
    time.sleep(0.5)  # simule la durée
    end = time.time()

    duration = end - start
    attempts = 7

    stats = {
        "host": "127.0.0.1",
        "attempts": attempts,
        "duration": duration,
        "rate": attempts / duration,
        "result": "ÉCHEC",
        "banner": "SSH-2.0-OpenSSH_8.9p1"
    }

    print_summary(stats)