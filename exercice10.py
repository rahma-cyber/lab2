import logging

logging.basicConfig(
    filename="brute_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def mask_password(pwd):
    if len(pwd) <= 2:
        return "*" * len(pwd)

    return "*" * (len(pwd) - 3) + pwd[-2:]

logging.info(f"Tentative : {mask_password('password123')}")