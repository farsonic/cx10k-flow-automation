#!/usr/bin/env python3

import redis
import argparse
import subprocess
import sys
import requests
import json
import os
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from tabulate import tabulate
from textwrap import wrap
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_CSV_FILE = "service-names-port-numbers.csv"
CONFIG_FILE = "config.json"

def load_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

config = load_config()

def download_iana_csv():
    if not os.path.exists(IANA_CSV_FILE):
        import urllib.request
        print("[*] Downloading IANA port mapping CSV...")
        urllib.request.urlretrieve(IANA_CSV_URL, IANA_CSV_FILE)
        print("[*] Download complete.")

def load_iana_portnames():
    port_service_map = {}
    with open(IANA_CSV_FILE, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            port = row.get('Port Number', '').strip()
            proto = row.get('Transport Protocol', '').strip().lower()
            name = row.get('Service Name', '').strip().lower()
            if port.isdigit() and name:
                key = (proto, port)
                if key not in port_service_map:
                    port_service_map[key] = name
    return port_service_map

download_iana_csv()
PORT_SERVICE_MAP = load_iana_portnames()

def pretty_app_name(proto, port):
    key = (proto, str(port))
    name = PORT_SERVICE_MAP.get(key)
    if name:
        return name.replace("-", "_")  # Always underscores
    return f"{proto}_{port}"

def best_app_name(proto, port):
    key = (proto, str(port))
    service = PORT_SERVICE_MAP.get(key)
    if service:
        return service.replace("-", "_").lower()
    return f"{proto}_{port}"

def dedup(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]

PROTO_MAP = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp"
}

parser = argparse.ArgumentParser(description="Manage VLAN-based network policies via Python.")
parser.add_argument('--srcvlan', help='Show dependencies only for this source VLAN')
parser.add_argument('--destvlan', help='Show dependencies only for this destination VLAN')
parser.add_argument('--since', type=str, help="Only include logs since time window (e.g. 30m, 12h, 7d, 3M, 1y)")
parser.add_argument('--apply', action='store_true', help="Apply all discovered policies/apps/collections now")
parser.add_argument('--remove', action='store_true', help="Remove a policy or just a rule from it")
parser.add_argument('--rule-name', help='Rule name to remove from the specified policy (if not provided, deletes the whole policy)')
parser.add_argument('--dry', action='store_true', help="Show summary table only (no apply/remove)")
parser.add_argument('--analyse', action='store_true', help="Send summary table to OpenAI and get analysis/recommendations")
parser.add_argument('--policy-name', default='auto_policy', help='Policy name (default: auto_policy)')
parser.add_argument('--vlan-list', action='store_true', help='List all unique VLANs seen in the data')
parser.add_argument('--capacity', action='store_true', help='Show Redis DB stats and usage')
parser.add_argument('--debug', action='store_true', help="Print detailed steps")
args = parser.parse_args()
FILTER_SRC_VLAN = args.srcvlan
FILTER_DEST_VLAN = args.destvlan
SINCE_ARG = args.since
POLICY_NAME = args.policy_name

def parse_since(since):
    if not since:
        return None
    now = datetime.now()
    try:
        if since.endswith("m"):
            return now - timedelta(minutes=int(since[:-1]))
        elif since.endswith("h"):
            return now - timedelta(hours=int(since[:-1]))
        elif since.endswith("d"):
            return now - timedelta(days=int(since[:-1]))
        elif since.endswith("M"):
            return now - timedelta(days=30*int(since[:-1]))
        elif since.endswith("y"):
            return now - timedelta(days=365*int(since[:-1]))
        else:
            return now - timedelta(hours=int(since))
    except Exception:
        return None

SINCE_DT = parse_since(SINCE_ARG)
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"

r = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

def print_redis_capacity():
    info = r.info()
    session_keys = list(r.scan_iter('session:*'))
    print("\n[REDIS CAPACITY REPORT]")
    print(f"  Redis version      : {info.get('redis_version','?')}")
    print(f"  Uptime (seconds)   : {info.get('uptime_in_seconds','?')}")
    print(f"  Used memory (bytes): {info.get('used_memory','?')}")
    print(f"  Used memory (MB)   : {round(int(info.get('used_memory',0))/1024/1024, 2)}")
    print(f"  Max memory (bytes) : {info.get('maxmemory','?')}")
    print(f"  Total keys         : {info.get('db0',{}).get('keys','?') if 'db0' in info else '?'}")
    print(f"  Session records    : {len(session_keys)}")
    print(f"  Memory policy      : {info.get('maxmemory_policy','?')}")
    print(f"  Evicted keys       : {info.get('evicted_keys','?')}")
    print(f"  Expired keys       : {info.get('expired_keys','?')}")
    print(f"  Connected clients  : {info.get('connected_clients','?')}")
    print()

def load_config():
    with open('config.json', 'r') as file:
        return json.load(file)

def ObtainPSMToken():
    config = load_config()
    psmipaddress = config['psmipaddress']
    psmusername = config['psmusername']
    psmpassword = config['psmpassword']
    url = f"https://{psmipaddress}/v1/login"
    credentials = {"username": psmusername, "password": psmpassword, "tenant": "default"}
    headers = {"Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, data=json.dumps(credentials), verify=False, timeout=5)
    resp.raise_for_status()
    return resp.headers['Set-Cookie']

def constructHeader(token):
    headers = {}
    headers["Content-Type"] = "application/json"
    headers['accept'] = "application/json; version=1.0"
    headers["cookie"] = token
    return headers

def get_app_definition(app_name, debug=False):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/apps/{app_name}"
    token = ObtainPSMToken()
    headers = constructHeader(token)
    try:
        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code == 200:
            return resp.json()
        else:
            return None
    except Exception as e:
        if debug:
            print(f"[DEBUG] Exception in get_app_definition: {e}")
        return None

def app_matches(current_app, proto_name, port):
    try:
        proto_ports = current_app['spec']['proto-ports']
        for pp in proto_ports:
            if pp['protocol'].lower() == proto_name.lower() and str(pp['ports']) == str(port):
                return True
        return False
    except Exception:
        return False

def policy_exists(policy_name):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/networksecuritypolicies/{policy_name}"
    token = ObtainPSMToken()
    headers = constructHeader(token)
    try:
        resp = requests.get(url, headers=headers, verify=False)
        return resp.status_code == 200
    except Exception:
        return False

def remove_catch_all_rule(policy_name, debug=True):
    try:
        run_step([
            "python3", "rule_manager.py", "remove_rule",
            "--policy_name", policy_name,
            "--rule_name", "catch_all"
        ], debug=debug)
    except SystemExit:
        pass

def get_vlan_sessions():
    sessions = []
    for key in r.scan_iter('session:*'):
        sess = r.hgetall(key)
        try:
            start_time_str = sess.get('start_time')
            if SINCE_DT and start_time_str:
                sess_time = datetime.strptime(start_time_str, TIME_FMT)
                if sess_time < SINCE_DT:
                    continue
            src_vlan = sess.get('sourceprimaryvlan')
            dst_vlan = sess.get('destprimaryvlan')
            src_ip   = sess.get('src_ip')
            dst_ip   = sess.get('dst_ip')
            dst_port = sess.get('dst_port')
            proto    = sess.get('proto', '6')
            app      = sess.get('dst_app')
            if src_vlan and dst_vlan and src_ip and dst_ip and dst_port:
                if (not FILTER_SRC_VLAN or src_vlan == FILTER_SRC_VLAN) and (not FILTER_DEST_VLAN or dst_vlan == FILTER_DEST_VLAN):
                    sessions.append((src_vlan, dst_vlan, f"{src_ip}/32", f"{dst_ip}/32", dst_port, proto, app))
        except Exception:
            pass
    return sessions

def build_dependency_table(sessions):
    table = []
    agg = {}
    for src_vlan, dst_vlan, src_ip, dst_ip, dst_port, proto, app in sessions:
        key = (src_vlan, dst_vlan, src_ip, dst_ip, dst_port, proto, app)
        if key not in agg:
            agg[key] = 0
        agg[key] += 1
    for (src_vlan, dst_vlan, src_ip, dst_ip, dst_port, proto, app), flows in agg.items():
        table.append((
            src_vlan,
            dst_vlan,
            src_ip,
            dst_ip,
            dst_port,
            proto,
            app,
            flows
        ))
    return table

def run_step(cmd, debug=True):
    if debug:
        print("  →", " ".join(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"[ERROR] Command failed: {' '.join(cmd)}")
        sys.exit(result.returncode)

def get_rule_map(table):
    apps = set()
    src_collections = defaultdict(set)
    dst_collections = defaultdict(set)
    rule_map = defaultdict(set)
    for row in table:
        src_vlan = row[0]
        dst_vlan = row[1]
        src_ip = row[2].replace("/32", "")
        dst_ip = row[3].replace("/32", "")
        dst_port = row[4]
        proto = row[5]
        proto_name = PROTO_MAP.get(str(proto), str(proto))
        api_app = best_app_name(proto_name, dst_port)
        apps.add((api_app, proto_name, dst_port))
        src_collections[src_vlan].add(src_ip)
        dst_collections[dst_vlan].add(dst_ip)
        rule_map[(src_vlan, dst_vlan)].add((proto_name, dst_port))
    return apps, src_collections, dst_collections, rule_map

def print_summary_table(rule_map, policy_name="auto_policy"):
    summary_rows = []
    for (src_vlan, dst_vlan), proto_port_set in sorted(rule_map.items()):
        src_col = f"vlan{src_vlan}_hosts"
        dst_col = f"vlan{dst_vlan}_hosts"
        rule_name = f"vlan{src_vlan}_to_vlan{dst_vlan}"
        apps_pretty = dedup([pretty_app_name(proto, port) for (proto, port) in sorted(proto_port_set)])
        apps_arg_wrapped = "\n".join(wrap(", ".join(apps_pretty), width=60))
        summary_rows.append([policy_name, rule_name, src_col, dst_col, apps_arg_wrapped])
    print("\n[PLANNED POLICY STRUCTURE]")
    print(tabulate(
        summary_rows,
        headers=["Policy", "Rule Name", "Source VLAN", "Dest VLAN", "Applications"],
        tablefmt="fancy_grid"
    ))
    return summary_rows  # So we can use it for GPT analysis

def list_all_vlans():
    src_vlans = set()
    dst_vlans = set()
    for key in r.scan_iter('session:*'):
        sess = r.hgetall(key)
        if SINCE_DT and 'start_time' in sess:
            try:
                sess_time = datetime.strptime(sess['start_time'], TIME_FMT)
                if sess_time < SINCE_DT:
                    continue
            except Exception:
                pass
        if 'sourceprimaryvlan' in sess:
            src_vlans.add(sess['sourceprimaryvlan'])
        if 'destprimaryvlan' in sess:
            dst_vlans.add(sess['destprimaryvlan'])
    all_vlans = sorted(src_vlans | dst_vlans, key=lambda v: int(v))
    print("Discovered VLANs:")
    for vlan in all_vlans:
        print(f"  VLAN {vlan}")

def apply_policy(table, policy_name="auto_policy", debug=True):
    apps, src_collections, dst_collections, rule_map = get_rule_map(table)
    required_api_apps = set()
    app_to_proto_port = {}
    for (api_app, proto_name, port) in apps:
        required_api_apps.add(api_app)
        app_to_proto_port[api_app] = (proto_name, port)

    print("\n[STEP] Creating Apps...")
    for api_name in sorted(required_api_apps):
        proto_name, port = app_to_proto_port[api_name]
        current_app = get_app_definition(api_name, debug=debug)
        if current_app:
            if app_matches(current_app, proto_name, port):
                print(f"[INFO] App '{api_name}' already exists with matching proto-port. Skipping creation.")
                continue
            else:
                print(f"[WARNING] App '{api_name}' exists but with different proto-port(s). Please review before overwriting. Skipping.")
                continue
        run_step(["python3", "rule_manager.py", "create_app", "--name", api_name, "--definitions", f"{proto_name}:{port}"], debug=debug)

    print("\n[STEP] Creating Source/Destination IP Collections...")
    created_collections = set()
    for vlan, ips in sorted(src_collections.items()):
        cname = f"vlan{vlan}_hosts"
        if cname not in created_collections:
            run_step(["python3", "rule_manager.py", "ip_collection", "--add-ipcollection", "--name", cname, "--addresses"] + list(sorted(ips)), debug=debug)
            created_collections.add(cname)
    for vlan, ips in sorted(dst_collections.items()):
        cname = f"vlan{vlan}_hosts"
        if cname not in created_collections:
            run_step(["python3", "rule_manager.py", "ip_collection", "--add-ipcollection", "--name", cname, "--addresses"] + list(sorted(ips)), debug=debug)
            created_collections.add(cname)

    print("\n[STEP] Creating Policy...")
    if policy_exists(policy_name):
        print(f"[INFO] Policy '{policy_name}' already exists. Skipping creation.")
    else:
        run_step(["python3", "rule_manager.py", "create_policy", "--name", policy_name], debug=debug)

    print("\n[STEP] Adding Permit Rules...")
    summary_rows = []
    for (src_vlan, dst_vlan), proto_port_set in sorted(rule_map.items()):
        src_col = f"vlan{src_vlan}_hosts"
        dst_col = f"vlan{dst_vlan}_hosts"
        rule_name = f"vlan{src_vlan}_to_vlan{dst_vlan}"
        apps_api_names = dedup([best_app_name(proto, port) for (proto, port) in sorted(proto_port_set)])
        apps_pretty = apps_api_names
        run_step([
            "python3", "rule_manager.py", "add_rule",
            "--policy_name", policy_name,
            "--rule_name", rule_name,
            "--apps", ",".join(apps_api_names),
            "--action", "permit",
            "--from_ip_collections", src_col,
            "--to_ip_collections", dst_col
        ], debug=debug)
        summary_rows.append([policy_name, rule_name, src_col, dst_col, ", ".join(apps_pretty)])

    remove_catch_all_rule(policy_name, debug=debug)
    print("\n[STEP] Adding Catch-All Rule...")
    action = input("Catch-all rule action for all other flows [deny/permit]? (default: deny): ").strip().lower()
    if action not in ['permit', 'deny']:
        action = 'deny'
    run_step([
        "python3", "rule_manager.py", "add_rule",
        "--policy_name", policy_name,
        "--rule_name", "catch_all",
        "--action", action,
        "--proto_ports", "any:",
        "--from_source_ip", "any",
        "--to_destination_ip", "any",
        "--description", "Catch-all for all other flows"
    ], debug=debug)

    print("\n[SUMMARY] Policy Table:")
    for row in summary_rows:
        row[4] = "\n".join(wrap(row[4], width=60))
    print(tabulate(summary_rows, headers=["Policy", "Rule Name", "Source VLAN", "Dest VLAN", "Applications"], tablefmt="fancy_grid"))
    print(f"\nCatch-all rule: action = {action}")

def remove_policy(table, policy_name="auto_policy", rule_name=None, debug=True):
    if rule_name:
        print(f"\n[REMOVE] Deleting Rule '{rule_name}' from Policy '{policy_name}' ...")
        run_step([
            "python3", "rule_manager.py", "remove_rule",
            "--policy_name", policy_name,
            "--rule_name", rule_name
        ], debug=debug)
        print(f"[INFO] Rule '{rule_name}' deleted from policy '{policy_name}'.")
    else:
        print(f"\n[REMOVE] Deleting Policy '{policy_name}' ...")
        run_step(["python3", "rule_manager.py", "delete_policy", "--name", policy_name], debug=debug)
        print(f"[INFO] Policy '{policy_name}' deleted. (Apps and IP collections are not deleted.)")

def print_table(table):
    headers = [
        "Source VLAN", "Dest VLAN", "Source IP/32", "Dest IP/32", "Dest Port", "Proto", "App", "Num Flows"
    ]
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

def analyse_policy_table(summary_rows):
    import openai
    table_md = tabulate(
        summary_rows,
        headers=["Policy", "Rule Name", "Source VLAN", "Dest VLAN", "Applications"],
        tablefmt="github"
    )
    internet_vlan = input("Which VLAN is the Internet-facing VLAN? (e.g. 99): ").strip()
    prompt = (
        "You are a network security analyst. Given the following DC application dependency policy table (with VLANs and allowed applications/ports), "
        "provide a detailed security review with specific recommendations. Highlight any potentially risky or misconfigured flows—"
        "especially traffic going to or from the Internet VLAN (which is VLAN {}). "
        "Call out protocols/ports that are rarely needed for Internet access, or are a high risk if allowed (e.g., SNMP, syslog, LDAP, redis, msft_gc, ssh, etc). "
        "Summarize each VLAN's apparent function based on the flows, and suggest any firewall or segmentation or microsegmentation improvements."
        "The network is using Aruba CX10000 switches as the top of rack connected to workloads"
        "\n\nPolicy Table:\n\n"
        "{}"
        "\n\nBe specific about which flows, apps or rules should be denied or reviewed. End with a security posture rating and recommendations."
    ).format(internet_vlan, table_md)

    model = config.get("openai_model", "gpt-4o")
    key = config.get("openai_api_key")
    if not key:
        print("[ERROR] No OpenAI API key in config.json (key: openai_api_key)")
        sys.exit(1)
    openai.api_key = key
    print(f"\n[OPENAI {model}] Analysing policy table. Please wait...")
    response = openai.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": "You are a world-class datacenter network security reviewer."},
                  {"role": "user", "content": prompt}]
    )
    summary = response.choices[0].message.content.strip()
    print("\n" + "="*30 + " AI SECURITY ANALYSIS " + "="*30 + "\n")
    print(summary)
    print("\n" + "="*78 + "\n")

if __name__ == "__main__":
    if args.capacity:
        print_redis_capacity()
        sys.exit(0)
    if args.vlan_list:
        list_all_vlans()
        sys.exit(0)

    sessions = get_vlan_sessions()
    if not sessions:
        print("\n[INFO] No sessions found for the current filter (window, VLANs, etc). Exiting.\n")
        sys.exit(0)

    table = build_dependency_table(sessions)
    _, _, _, rule_map = get_rule_map(table)

    if args.analyse:
        summary_rows = print_summary_table(rule_map, policy_name=POLICY_NAME)
        analyse_policy_table(summary_rows)
    elif args.apply:
        apply_policy(table, policy_name=POLICY_NAME, debug=args.debug)
    elif args.remove:
        remove_policy(table, policy_name=POLICY_NAME, rule_name=args.rule_name, debug=args.debug)
    else:
        # DEFAULT: --dry summary table if no --apply, --remove, --analyse
        summary_rows = print_summary_table(rule_map, policy_name=POLICY_NAME)
        print("\nCatch-all rule: action = [permit|deny] (choose when applying)")
