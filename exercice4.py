def load_wordlist(path):
    with open(path, encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f]
    return [l for l in lines if l and not l.startswith('#')]