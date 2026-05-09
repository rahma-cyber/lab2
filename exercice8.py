import threading, queue

def worker(host, port, username, q, stop_event, lock, max_per_thread=3):
    attempts = 0
    while not stop_event.is_set() and attempts < max_per_thread:
        try:
            password = q.get(timeout=1)
        except queue.Empty:
            break
        result = try_ssh_login(host, port, username, password)
        with lock:
            print(result)
        if result["outcome"] == "success":
            stop_event.set()
        q.task_done()
        attempts += 1