#!/usr/bin/env python3

import socket
import datetime
import uuid
import random
import time
import argparse

parser = argparse.ArgumentParser(description="Send DC-style syslog flows for web/app/db/internet tiers")
parser.add_argument('--count', type=int, default=20, help='Number of sessions to send')
parser.add_argument('--rate', type=int, default=5, help='Sessions per second')
parser.add_argument('--host', default="127.0.0.1", help='Syslog target IP')
parser.add_argument('--port', type=int, default=5514, help='Syslog target port')
parser.add_argument('--offset', type=int, default=12, help='Timestamp offset in hours')
args = parser.parse_args()

COUNT = args.count
RATE = max(1, min(args.rate, 1000))
SYSLOG_HOST = args.host
SYSLOG_PORT = args.port
OFFSET_HOURS = args.offset
DELAY = 1.0 / RATE

# --- VLAN/Subnet Definitions ---
WEB_VLAN   = "10"; WEB_NET   = "10.10.10."
APP_VLAN   = "20"; APP_NET   = "10.10.20."
DB_VLAN    = "30"; DB_NET    = "10.10.30."
INET_VLAN  = "99"; INET_NET  = "192.168.99."
MALICIOUS_IPS = ["1.169.140.14", "94.103.94.154", "173.248.147.186"]

# --- Well-known ports (max 20) ---
WELL_KNOWN_PORTS = {
    "web":   [80, 443, 8080, 8443],
    "app":   [3000, 8000, 8081, 9000],
    "db":    [3306, 5432, 1433],
    "infra": [389, 636, 3268],
    "msg":   [5672, 6379, 11211],
    "mon":   [161, 514, 123],
    "misc":  [22],
}
# Flatten to max 20
ALL_PORTS = WELL_KNOWN_PORTS["web"] + WELL_KNOWN_PORTS["app"] + WELL_KNOWN_PORTS["db"] + \
            WELL_KNOWN_PORTS["infra"] + WELL_KNOWN_PORTS["msg"] + WELL_KNOWN_PORTS["mon"] + WELL_KNOWN_PORTS["misc"]
ALL_PORTS = ALL_PORTS[:20]

# --- Tier to port mapping for realism ---
TIER_PORTS = {
    "web":   WELL_KNOWN_PORTS["web"],
    "app":   WELL_KNOWN_PORTS["app"] + WELL_KNOWN_PORTS["infra"] + WELL_KNOWN_PORTS["msg"],
    "db":    WELL_KNOWN_PORTS["db"],
    "inet":  [80, 443, 123, 514],
    "infra": WELL_KNOWN_PORTS["infra"] + WELL_KNOWN_PORTS["mon"] + [22],
    "msg":   WELL_KNOWN_PORTS["msg"],
}

WEB_HOSTS = [f"{WEB_NET}{i}" for i in range(2, 10)]
APP_HOSTS = [f"{APP_NET}{i}" for i in range(2, 10)]
DB_HOSTS  = [f"{DB_NET}{i}"  for i in range(2, 10)]
INET_HOSTS = [f"{INET_NET}{i}" for i in range(2, 10)] + MALICIOUS_IPS

def pick_flow():
    """Return (src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, description)"""
    flows = [
        # Web -> App (HTTP, HTTPS, API)
        (WEB_HOSTS, WEB_VLAN, APP_HOSTS, APP_VLAN, TIER_PORTS["app"], 6, "web->app"),
        # App -> DB (DB, cache, msg)
        (APP_HOSTS, APP_VLAN, DB_HOSTS, DB_VLAN, TIER_PORTS["db"], 6, "app->db"),
        # Web -> Internet (egress, NTP, syslog)
        (WEB_HOSTS, WEB_VLAN, INET_HOSTS, INET_VLAN, TIER_PORTS["inet"], random.choice([6, 17]), "web->inet"),
        # App -> Internet (API, NTP)
        (APP_HOSTS, APP_VLAN, INET_HOSTS, INET_VLAN, TIER_PORTS["inet"], random.choice([6, 17]), "app->inet"),
        # DB -> App (DB replies)
        (DB_HOSTS, DB_VLAN, APP_HOSTS, APP_VLAN, TIER_PORTS["app"], 6, "db->app"),
        # App -> Infra (LDAP, syslog)
        (APP_HOSTS, APP_VLAN, INET_HOSTS, INET_VLAN, TIER_PORTS["infra"], 6, "app->infra"),
        # Malicious flows
        (WEB_HOSTS, WEB_VLAN, MALICIOUS_IPS, INET_VLAN, [443, 8080], 6, "web->mal"),
        (APP_HOSTS, APP_VLAN, MALICIOUS_IPS, INET_VLAN, [22, 514], 6, "app->mal"),
    ]
    flow = random.choice(flows)
    src_ip = random.choice(flow[0])
    src_vlan = flow[1]
    dst_ip = random.choice(flow[2])
    dst_vlan = flow[3]
    dst_port = str(random.choice(flow[4]))
    proto = flow[5]
    desc = flow[6]
    return src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, desc

def generate_payload(past_time, session_id, session_uuid, src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, is_create, flowdesc):
    timestamp = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    rule_action = "allow"
    flowaction = "flow_create" if is_create else "flow_delete"
    src_port = random.randint(1024, 65535)
    policy_id = uuid.uuid4()
    rule_id = random.randint(1, 99999)
    rulename = {"web->app":"allow-http", "app->db":"allow-mysql", "db->app":"allow-mysql", "web->inet":"allow-egress", "app->inet":"allow-update", "web->mal":"deny-all", "app->mal":"deny-all", "app->infra": "allow-ldap"}.get(flowdesc, "allow-custom")
    iflowpkts = random.randint(100, 1000)
    iflowbytes = random.randint(2000, 100000)
    rflowpkts = random.randint(50, 500)
    rflowbytes = random.randint(1000, 50000)
    vlan = src_vlan
    encrypted_str = random.choice(["true", "false"])
    direction = random.choice(["from-host", "uplink"])
    if is_create:
        createreason = "flow_miss"
        deletereason = "-"
    else:
        createreason = "-"
        if proto == 6:
            deletereason = random.choice(["tcp_full_close", "tcp_rst"])
        else:
            deletereason = "aging"
    dstvpcname = uuid.uuid4()
    dstvpcid = uuid.uuid4()
    dstvlan = dst_vlan
    session_flags = random.randint(0, 7)
    unitid = random.randint(1, 2)
    sourceprimaryvlan = src_vlan
    destprimaryvlan = dst_vlan
    srcvpcname = uuid.uuid4()
    nattranslatedsrcip = src_ip
    nattranslateddestip = dst_ip
    nattranslateddestport = dst_port
    fields = [
        timestamp, flowaction, rule_action, str(session_uuid),
        src_ip, str(src_port), dst_ip, str(dst_port),
        str(proto), str(session_id), str(policy_id), str(rule_id),
        rulename, str(iflowpkts), str(iflowbytes), str(rflowpkts),
        str(rflowbytes), vlan, "DSS", "10.14.1001", "SN0123456789",
        "00:11:22:33:44:55", str(unitid), "V3", "policy-1",
        "Policy Display Name", nattranslatedsrcip, nattranslateddestip, nattranslateddestport,
        encrypted_str, direction, createreason, deletereason,
        str(srcvpcname), str(dstvpcname), str(dstvpcid), dstvlan,
        str(session_flags), sourceprimaryvlan, destprimaryvlan
    ]
    return ",".join(fields)

def generate_syslog_message(payload, past_time):
    pri = 14
    version = 1
    timestamp = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = f"DCGW-{random.choice(['W','A','D','I'])}"
    appname = "pen-netagent"
    procid = str(random.randint(1000, 999999))
    msgid = "-"
    return f"<{pri}>{version} {timestamp} {hostname} {appname} {procid} {msgid} - {payload}"

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(COUNT):
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=OFFSET_HOURS)
        session_id = random.randint(100000, 999999)
        session_uuid = uuid.uuid4()
        src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, flowdesc = pick_flow()
        # Start
        payload_start = generate_payload(past_time, session_id, session_uuid, src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, True, flowdesc)
        msg_start = generate_syslog_message(payload_start, past_time)
        sock.sendto(msg_start.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
        print(f"[+] Sent session start: {flowdesc} {msg_start}")
        # End
        payload_end = generate_payload(past_time, session_id, session_uuid, src_ip, src_vlan, dst_ip, dst_vlan, dst_port, proto, False, flowdesc)
        msg_end = generate_syslog_message(payload_end, past_time)
        sock.sendto(msg_end.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
        print(f"[+] Sent session end: {flowdesc} {msg_end}")
        time.sleep(DELAY)
    sock.close()
    print(f"[✓] Sent {COUNT} DC multi-tier sessions (start/end logs) to {SYSLOG_HOST}:{SYSLOG_PORT} at ~{RATE} sessions/sec")

if __name__ == "__main__":
    main()
