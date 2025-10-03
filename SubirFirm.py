import json
import paramiko
import re
import time
from typing import Tuple, List

COMANDO = "request firmware onu add tftp://100.76.180.36/DATACOM/V1.5-1020W_250930.tar"

def extract_olt_ips(zabbix_json: dict) -> List[Tuple[str, str]]:
    olts = []
    for host in zabbix_json.get("zabbix_export", {}).get("hosts", []):
        hostname = host.get("host")
        for interface in host.get("interfaces", []):
            if interface.get("type") == "SNMP":
                ip = interface.get("ip")
                olts.append((hostname, ip))
    return olts

def ssh_execute_command(ip: str, username: str, password: str, command: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password, look_for_keys=False)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        return output
    except Exception as e:
        print(f"Erro ao conectar em {ip}: {e}")
        return ""
    finally:
        client.close()

def main():
    username = input("Usuário SSH: ")
    password = input("Senha SSH: ")

    with open("inventario_olts.json", "r") as f:
        zabbix_data = json.load(f)
        
    olts = extract_olt_ips(zabbix_data)


    for hostname, ip in olts:
        output = ssh_execute_command(ip, username, password, COMANDO)
        print(f'{hostname} - {ip} - {output}')
        if not output.strip():
            print(f"❌ Falha na coleta da OLT {hostname}")
            continue


if __name__ == "__main__":
    main()