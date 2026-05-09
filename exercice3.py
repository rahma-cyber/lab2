def try_ssh_login_with_banner(host, port, username, password, timeout=3.0):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    banner = None
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        outcome = "success"
    except paramiko.AuthenticationException:
        outcome = "failure"
    except (paramiko.SSHException, OSError) as e:
        return {"outcome": "error", "msg": str(e), "banner": None}
    finally:
        transport = client.get_transport()
        if transport:
            banner = transport.remote_version
        client.close()
    return {"outcome": outcome, "banner": banner}