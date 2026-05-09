import random

def sleep_with_jitter(min_s, max_s):
    time.sleep(random.uniform(min_s, max_s))

