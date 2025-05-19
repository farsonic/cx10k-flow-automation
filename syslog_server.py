#!/usr/bin/env python3

import socketserver
import redis
from datetime import datetime, timezone
import os
import socket
import argparse
import csv
import urllib.request
import json

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_CSV_FILE = "service-names-port-numbers.csv"

CONFIG_FILE = "config.json"

# ---- Load config ----
def load_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

config = load_config()
SESSION_TTL_DAYS = int(config.get("session_ttl_days", 7))
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60

OPENAI_API_KEY = config.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")

# ---- Argument for ChatGPT Enrichment ----
parser = argparse.ArgumentParser(description="Syslog server with optional ChatGPT enrichment and IANA port mapping")
parser.add_argument('--chatgpt', action='store_true', help="Enable ChatGPT enrichment")
parser.add_argument('--offload', action='store_true', help="Offload expired/old sessions to disk")
parser.add_argument('--offload-file', type=str, default="cxlogvault_offload.jsonl", help="Destination for offloaded logs (default: cxlogvault_offload.jsonl)")
args = parser.parse_args()
ENABLE_CHATGPT = args.chatgpt or os.environ.get("ENABLE_CHATGPT", "0") == "1"

if ENABLE_CHATGPT and OPENAI_API_KEY:
    import openai
    openai.api_key = OPENAI_API_KEY

# ---- Redis setup ----
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# ---- CSV Headers ----
CSV_HEADERS = [
    "timestamp", "flowaction", "rule_action", "session_uuid", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
    "sessionid", "policy_id", "rule_id", "rulename", "iflowpkts", "iflowbytes", "rflowpkts", "rflowbytes", "vlan",
    "producttype", "softwareversion", "serialnumber", "devicemac", "unitid", "version", "policyname",
    "policydisplayname", "nattranslatedsrcip", "nattranslateddestip", "nattranslateddestport", "encrypted",
    "direction", "createreason", "deletereason", "srcvpcname", "dstvpcname", "dstvpcid", "dstvlan", "sessionflags",
    "sourceprimaryvlan", "destprimaryvlan"
]

def download_iana_csv():
    if not os.path.isfile(IANA_CSV_FILE):
        print("[*] Downloading IANA port mapping CSV...")
        urllib.request.urlretrieve(IANA_CSV_URL, IANA_CSV_FILE)
        print("[*] Download complete.")

def load_iana_portmap(csv_file):
    portmap = {}
    with open(csv_file, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            port = row['Port Number']
            proto = row['Transport Protocol'].lower()
            name = row['Service Name']
            if port.isdigit() and name:
                portmap[(int(port), proto)] = name
    return portmap

def map_port_to_app(port, proto, iana_portmap):
    try:
        port_int = int(port)
        proto_str = str(proto).lower()
        app = iana_portmap.get((port_int, proto_str))
        if app and app != "-":
            return app
        if proto_str == "6" or proto_str == "tcp":
            return socket.getservbyport(port_int, 'tcp')
        elif proto_str == "17" or proto_str == "udp":
            return socket.getservbyport(port_int, 'udp')
        else:
            return "unknown"
    except Exception:
        return "unknown"

def decode_session_flags(flags):
    """Decode sessionflags integer and return a dict of named flags."""
    try:
        flags = int(flags)
        return {
            "stateless":  int(bool(flags & 1)),
            "encrypted":  int(bool(flags & 2)),
            "fragmented": int(bool(flags & 4)),
            "nated":      int(bool(flags & 8)),
            "dropped":    int(bool(flags & 16)),
            "inspected":  int(bool(flags & 32)),
            "forwarded":  int(bool(flags & 64)),
        }
    except Exception:
        return {}

def enrich_with_chatgpt(session_data):
    if not ENABLE_CHATGPT:
        return ""
    prompt = (
        f"Summarize this network session and suggest security and dependency insights:\n{session_data}\n"
        "Include who initiated, VLAN, protocols, bytes transferred, and what is likely happening."
    )
    try:
        response = openai.chat.completions.create(
            model="gpt-4-1106-preview",
            messages=[{"role": "user", "content": prompt}]
        )
        summary = response.choices[0].message.content.strip()
        return summary
    except Exception as e:
        print("ChatGPT error:", e)
        return ""

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip().decode("utf-8")
        try:
            payload = data.split(" - ", 1)[1]
            fields = payload.split(",")
            sessionid = fields[9]
            action = fields[1]
            redis_key = f"session:{sessionid}"
            session_data = dict(zip(CSV_HEADERS, fields))
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Port/Application mapping (IANA)
            dst_port = session_data.get("dst_port")
            proto = session_data.get("proto")
            app = map_port_to_app(dst_port, proto, PORTMAP)
            session_data["dst_app"] = app

            # ---- DECODE AND STORE FLAGS ----
            flags_dict = decode_session_flags(session_data.get("sessionflags", "0"))
            session_data.update(flags_dict)

            # Store/update full session (with TTL)
            redis_client.hset(redis_key, mapping=session_data)
            redis_client.expire(redis_key, SESSION_TTL_SECONDS)
            if action == "flow_create":
                redis_client.hset(redis_key, "start_time", now)
            elif action == "flow_delete":
                redis_client.hset(redis_key, "end_time", now)
                # Calculate duration if possible
                start_ts = redis_client.hget(redis_key, "start_time")
                if start_ts:
                    fmt = "%Y-%m-%dT%H:%M:%SZ"
                    try:
                        t0 = datetime.strptime(start_ts, fmt)
                        t1 = datetime.strptime(now, fmt)
                        duration = (t1 - t0).total_seconds()
                        redis_client.hset(redis_key, "duration_seconds", str(duration))
                    except Exception:
                        pass
                # Calculate byte totals
                try:
                    total_bytes = int(session_data.get("iflowbytes", 0)) + int(session_data.get("rflowbytes", 0))
                    redis_client.hset(redis_key, "total_bytes", str(total_bytes))
                except Exception:
                    pass

                # ChatGPT enrichment (if enabled)
                if ENABLE_CHATGPT and OPENAI_API_KEY:
                    chatgpt_summary = enrich_with_chatgpt(session_data)
                    redis_client.hset(redis_key, "gpt_summary", chatgpt_summary)
                    print("Enriched session:", chatgpt_summary)

                # Correlation (simple example)
                src = session_data.get("src_ip")
                dst = session_data.get("dst_ip")
                vlan_a = session_data.get("sourceprimaryvlan")
                vlan_b = session_data.get("destprimaryvlan")
                if vlan_a and vlan_b:
                    redis_client.sadd(f"vlan_dep:{vlan_a}", vlan_b)
                    redis_client.sadd(f"vlan_dep:{vlan_b}", vlan_a)
                vlan = session_data.get("vlan")
                if src and dst and vlan:
                    redis_client.sadd(f"dep:{src}:{vlan}", dst)
                    redis_client.sadd(f"dep:{dst}:{vlan}", src)

            print(f"[+] Captured session: {sessionid} {action} (dst_app: {session_data['dst_app']})")

        except Exception as e:
            print("Parse/store error:", e)

def offload_old_sessions(outfile="cxlogvault_offload.jsonl", days_older=7):
    print(f"[OFFLOAD] Scanning for sessions about to expire...")
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - (days_older * 24 * 3600)
    count = 0
    with open(outfile, "a") as outf:
        for key in redis_client.scan_iter('session:*'):
            try:
                sess = redis_client.hgetall(key)
                # Only sessions with an end_time
                if "end_time" in sess:
                    end_dt = datetime.strptime(sess['end_time'], "%Y-%m-%dT%H:%M:%SZ")
                    if end_dt.timestamp() < cutoff:
                        outf.write(json.dumps(sess) + "\n")
                        redis_client.delete(key)
                        count += 1
            except Exception:
                continue
    print(f"[OFFLOAD] Offloaded and deleted {count} old sessions to {outfile}")

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 5514
    status = "enabled" if ENABLE_CHATGPT else "DISABLED"
    print(f"CXLogVault syslog server listening on UDP {PORT} (ChatGPT {status})")
    print(f"Session retention: {SESSION_TTL_DAYS} days (set in config.json)")
    if "redis_maxmemory_mb" in config:
        print(f"NOTE: Set 'maxmemory {config['redis_maxmemory_mb']}mb' in your redis.conf for memory limit enforcement!")
    download_iana_csv()
    PORTMAP = load_iana_portmap(IANA_CSV_FILE)

    if args.offload:
        offload_old_sessions(outfile=args.offload_file, days_older=SESSION_TTL_DAYS)
        sys.exit(0)

    with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
        server.serve_forever()
