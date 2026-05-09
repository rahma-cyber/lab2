import paramiko, socket

def try_ssh_login(host, port, username, password, timeout=3.0):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        return {"outcome": "success", "host": host, "user": username}
    except paramiko.AuthenticationException:
        return {"outcome": "failure", "host": host, "user": username}
    except (paramiko.SSHException, OSError, socket.error) as e:
        return {"outcome": "error", "host": host, "user": username, "msg": str(e)}
    finally:
        client.close()