#!/usr/bin/env python3

import requests
import argparse
import sys
import json
import urllib3
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Config and Session Helpers ===

def load_config():
    with open('config.json', 'r') as file:
        return json.load(file)

def obtain_psm_cookie():
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

def construct_headers(cookie):
    return {
        "Content-Type": "application/json",
        "accept": "application/json; version=1.0",
        "cookie": cookie
    }

# === Application CRUD ===

def create_app(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/apps"
    headers = construct_headers(cookie)
    proto_ports = []
    for entry in args.definitions:
        proto, port = entry.split(":")
        proto_ports.append({"protocol": proto, "ports": port})
    app_data = {
        "kind": "App",
        "api-version": "v1",
        "meta": {
            "name": args.name,
            "tenant": "default"
        },
        "spec": {
            "proto-ports": proto_ports
        }
    }
    if getattr(args, 'debug', False):
        print("=== POST URL ===")
        print(url)
        print("=== POST Payload ===")
        print(json.dumps(app_data, indent=2))
    try:
        response = requests.post(url, headers=headers, json=app_data, verify=False)
        response.raise_for_status()
        print(f"Application '{args.name}' created successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error creating application: {e}")

def delete_app(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/apps/{args.name}"
    headers = construct_headers(cookie)
    if getattr(args, 'debug', False):
        print("=== DELETE URL ===")
        print(url)
    try:
        response = requests.delete(url, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Application '{args.name}' deleted successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error deleting application: {e}")

# === IP Collection CRUD ===

def handle_ip_collections(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    headers = construct_headers(cookie)
    if args.add_ipcollection:
        url = f"https://{psmipaddress}/configs/network/v1/ipcollections"
        addresses = args.addresses if args.addresses else []
        ipcollections = [args.add_to_ipcollection] if args.add_to_ipcollection else []
        ipcol_data = {
            "kind": "IPCollection",
            "api-version": "v1",
            "meta": {
                "name": args.name,
                "tenant": "default"
            },
            "spec": {
                "addresses": addresses,
                "ipcollections": ipcollections,
                "AddressFamily": args.address_family or "IPv4"
            }
        }
        if args.labels:
            ipcol_data["meta"]["labels"] = json.loads(args.labels)
        if getattr(args, 'debug', False):
            print("=== POST URL ===")
            print(url)
            print("=== POST Payload ===")
            print(json.dumps(ipcol_data, indent=2))
        try:
            response = requests.post(url, headers=headers, json=ipcol_data, verify=False)
            if response.status_code == 409:
                # Update existing
                url2 = f"https://{psmipaddress}/configs/network/v1/ipcollections/{args.name}"
                response2 = requests.get(url2, headers=headers, verify=False)
                response2.raise_for_status()
                ipcol = response2.json()
                if addresses:
                    ipcol['spec']['addresses'] = sorted(list(set(ipcol['spec'].get('addresses', []) + addresses)))
                if ipcollections:
                    ipcol['spec']['ipcollections'] = sorted(list(set(ipcol['spec'].get('ipcollections', []) + ipcollections)))
                ipcol['spec']['AddressFamily'] = args.address_family or "IPv4"
                if args.labels:
                    ipcol['meta']['labels'] = json.loads(args.labels)
                put_resp = requests.put(url2, headers=headers, json=ipcol, verify=False)
                put_resp.raise_for_status()
                print(f"IP collection {args.name} updated successfully.")
            else:
                response.raise_for_status()
                print(f"IP collection {args.name} added successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Error adding/updating IP collection: {e}")

    elif args.del_ipcollection:
        if not args.address:
            print("Error: --address argument is required when using --del-ipcollection.")
            return
        url2 = f"https://{psmipaddress}/configs/network/v1/ipcollections/{args.name}"
        headers = construct_headers(cookie)
        try:
            response = requests.get(url2, headers=headers, verify=False)
            response.raise_for_status()
            ipcol = response.json()
            if args.address in ipcol['spec']['addresses']:
                ipcol['spec']['addresses'].remove(args.address)
                put_resp = requests.put(url2, headers=headers, json=ipcol, verify=False)
                put_resp.raise_for_status()
                print(f"IP address {args.address} deleted successfully from IP collection {args.name}.")
            else:
                print(f"IP address {args.address} not found in IP collection {args.name}.")
        except Exception as e:
            print(f"Error deleting IP from collection: {e}")

# === Policy CRUD ===

def create_policy(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/networksecuritypolicies"
    headers = construct_headers(cookie)
    policy_data = {
        "kind": "NetworkSecurityPolicy",
        "api-version": "v1",
        "meta": {
            "name": args.name,
            "tenant": "default"
        },
        "spec": {
            "attach-tenant": True,
            "rules": [],
            "priority": args.priority,
            "policy-distribution-targets": [args.policy_dist_target or "default"]
        }
    }
    if getattr(args, 'debug', False):
        print("=== POST URL ===")
        print(url)
        print("=== POST Payload ===")
        print(json.dumps(policy_data, indent=2))
    try:
        response = requests.post(url, headers=headers, json=policy_data, verify=False)
        response.raise_for_status()
        print(f"Policy '{args.name}' created successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error creating policy: {e}")

def delete_policy(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    url = f"https://{psmipaddress}/configs/security/v1/tenant/default/networksecuritypolicies/{args.name}"
    headers = construct_headers(cookie)
    if getattr(args, 'debug', False):
        print("=== DELETE URL ===")
        print(url)
    try:
        response = requests.delete(url, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Policy '{args.name}' deleted successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error deleting policy: {e}")

# === Rule CRUD ===

def add_rule(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    get_url = f"https://{psmipaddress}/configs/security/v1/tenant/default/networksecuritypolicies/{args.policy_name}"
    headers = construct_headers(cookie)
    try:
        get_response = requests.get(get_url, headers=headers, verify=False)
        get_response.raise_for_status()
        policy = get_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving policy: {e}")
        return

    proto_ports = []
    if getattr(args, 'proto_ports', None):
        for entry in args.proto_ports.split(","):
            if ":" in entry:
                proto, ports = entry.split(":", 1)
                proto_ports.append({"protocol": proto, "ports": ports})
            else:
                proto_ports.append({"protocol": entry, "ports": ""})

    rule = {
        "name": args.rule_name,
        "action": args.action,
        "description": getattr(args, 'description', None),
        "disable": getattr(args, 'disable', False),
        "from-ip-addresses": args.from_source_ip.split(",") if getattr(args, 'from_source_ip', None) else [],
        "to-ip-addresses": args.to_destination_ip.split(",") if getattr(args, 'to_destination_ip', None) else [],
        "from-workload-groups": args.from_workload_group.split(",") if getattr(args, 'from_workload_group', None) else [],
        "to-workload-groups": args.to_workload_group.split(",") if getattr(args, 'to_workload_group', None) else [],
        "from-ipcollections": args.from_ip_collections.split(",") if getattr(args, 'from_ip_collections', None) else [],
        "to-ipcollections": args.to_ip_collections.split(",") if getattr(args, 'to_ip_collections', None) else []
    }
    if proto_ports:
        rule["proto-ports"] = proto_ports
    if getattr(args, 'apps', None):
        rule["apps"] = args.apps.split(",")
    rule = {k: v for k, v in rule.items() if v is not None and v != []}

    # Ensure 'rules' exists in policy spec
    if "rules" not in policy["spec"]:
        policy["spec"]["rules"] = []
    policy["spec"]["rules"].append(rule)

    if getattr(args, 'debug', False):
        print("=== PUT URL ===")
        print(get_url)
        print("=== PUT Payload ===")
        print(json.dumps(policy, indent=2))

    try:
        put_response = requests.put(get_url, headers=headers, json=policy, verify=False)
        put_response.raise_for_status()
        print(f"Rule '{args.rule_name}' added to policy '{args.policy_name}' successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error adding rule to policy: {e}")

def remove_rule_from_policy(args, cookie):
    config = load_config()
    psmipaddress = config['psmipaddress']
    get_url = f"https://{psmipaddress}/configs/security/v1/tenant/default/networksecuritypolicies/{args.policy_name}"
    headers = construct_headers(cookie)
    try:
        get_response = requests.get(get_url, headers=headers, verify=False)
        get_response.raise_for_status()
        policy = get_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving policy: {e}")
        return

    old_rules = policy['spec'].get('rules', [])
    new_rules = [r for r in old_rules if r.get('name') != args.rule_name]
    if len(old_rules) == len(new_rules):
        print(f"[INFO] Rule '{args.rule_name}' not found in policy '{args.policy_name}'. Skipping removal.")
        return
    policy['spec']['rules'] = new_rules

    if getattr(args, 'debug', False):
        print("=== PUT URL ===")
        print(get_url)
        print("=== PUT Payload ===")
        print(json.dumps(policy, indent=2))

    try:
        put_response = requests.put(get_url, headers=headers, json=policy, verify=False)
        put_response.raise_for_status()
        print(f"Rule '{args.rule_name}' deleted from policy '{args.policy_name}' successfully.")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to update policy: {e}")

def bulk_add_rules(args, cookie):
    try:
        with open(args.csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                rule_args = argparse.Namespace(
                    policy_name=row.get("policy_name"),
                    rule_name=row.get("rule_name"),
                    apps=row.get("apps"),
                    action=row.get("action"),
                    description=row.get("description"),
                    disable=row.get("disable") == "True",
                    from_source_ip=row.get("from_source_ip"),
                    to_destination_ip=row.get("to_destination_ip"),
                    from_workload_group=row.get("from_workload_group"),
                    to_workload_group=row.get("to_workload_group"),
                    from_ip_collections=row.get("from_ip_collections"),
                    to_ip_collections=row.get("to_ip_collections"),
                    proto_ports=row.get("proto_ports"),
                    debug=getattr(args, 'debug', False)
                )
                add_rule(rule_args, cookie)
    except FileNotFoundError:
        print(f"Error: CSV file '{args.csv_file}' not found.")
    except Exception as e:
        print(f"Error processing CSV file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Manage PSM applications, policies, IP collections, and rules.")
    parser.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')
    subparsers = parser.add_subparsers(dest="command")

    parser_create_app = subparsers.add_parser("create_app", help="Create an application")
    parser_create_app.add_argument("--name", required=True, help="Application name")
    parser_create_app.add_argument("--definitions", nargs='+', required=True, help="Definitions in the format protocol:port")

    parser_delete_app = subparsers.add_parser("delete_app", help="Delete an application")
    parser_delete_app.add_argument("--name", required=True, help="Application name")

    parser_ipcol = subparsers.add_parser("ip_collection", help="Manage IP collections (add/update/delete)")
    parser_ipcol.add_argument('--add-ipcollection', action='store_true', help='Add or update an IP collection')
    parser_ipcol.add_argument('--del-ipcollection', action='store_true', help='Delete an IP address from a collection (or the whole collection if empty)')
    parser_ipcol.add_argument('--name', type=str, required=True, help='Name of the IP collection')
    parser_ipcol.add_argument('--addresses', nargs='+', help='List of IP addresses/CIDRs to add')
    parser_ipcol.add_argument('--address', type=str, help='Single IP address to remove (for delete)')
    parser_ipcol.add_argument('--add-to-ipcollection', type=str, help='Comma-separated list of existing IP collection(s) to nest')
    parser_ipcol.add_argument('--address_family', type=str, help='Address family (e.g., "IPv4", "IPv6")')
    parser_ipcol.add_argument('--labels', type=str, help='Labels as JSON for the IP collection')
    parser_ipcol.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    parser_create_policy = subparsers.add_parser("create_policy", help="Create a policy")
    parser_create_policy.add_argument("--name", required=True, help="Policy name")
    parser_create_policy.add_argument("--priority", type=int, default=10, help="Policy priority")
    parser_create_policy.add_argument("--policy_dist_target", help="Policy distribution target")
    parser_create_policy.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    parser_delete_policy = subparsers.add_parser("delete_policy", help="Delete a policy")
    parser_delete_policy.add_argument("--name", required=True, help="Policy name")
    parser_delete_policy.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    parser_add_rule = subparsers.add_parser("add_rule", help="Add a rule to a policy")
    parser_add_rule.add_argument("--policy_name", required=True, help="Policy name")
    parser_add_rule.add_argument("--rule_name", required=True, help="Rule name")
    parser_add_rule.add_argument("--apps", help="Comma-separated list of applications")
    parser_add_rule.add_argument("--action", choices=["permit", "deny"], required=True, help="Action for the rule")
    parser_add_rule.add_argument("--proto_ports", help="Comma-separated proto:port entries (e.g. any: or tcp:80)")
    parser_add_rule.add_argument("--description", help="Rule description")
    parser_add_rule.add_argument("--disable", action='store_true', help="Disable the rule")
    parser_add_rule.add_argument("--from_source_ip", help="Comma-separated list of source IP addresses")
    parser_add_rule.add_argument("--to_destination_ip", help="Comma-separated list of destination IP addresses")
    parser_add_rule.add_argument("--from_workload_group", help="Comma-separated list of source workload groups")
    parser_add_rule.add_argument("--to_workload_group", help="Comma-separated list of destination workload groups")
    parser_add_rule.add_argument("--from_ip_collections", help="Comma-separated list of source IP collections")
    parser_add_rule.add_argument("--to_ip_collections", help="Comma-separated list of destination IP collections")
    parser_add_rule.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    parser_remove_rule = subparsers.add_parser("remove_rule", help="Remove a rule from a policy")
    parser_remove_rule.add_argument("--policy_name", required=True, help="Policy name")
    parser_remove_rule.add_argument("--rule_name", required=True, help="Rule name")
    parser_remove_rule.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    parser_bulk_add = subparsers.add_parser("bulk_add_rules", help="Bulk add rules from CSV")
    parser_bulk_add.add_argument("--csv_file", required=True, help="Path to CSV file")
    parser_bulk_add.add_argument('--debug', action='store_true', help='Enable debug logging and show request JSONs')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cookie = obtain_psm_cookie()

    if args.command == "create_app":
        create_app(args, cookie)
    elif args.command == "delete_app":
        delete_app(args, cookie)
    elif args.command == "ip_collection":
        handle_ip_collections(args, cookie)
    elif args.command == "create_policy":
        create_policy(args, cookie)
    elif args.command == "delete_policy":
        delete_policy(args, cookie)
    elif args.command == "add_rule":
        add_rule(args, cookie)
    elif args.command == "remove_rule":
        remove_rule_from_policy(args, cookie)
    elif args.command == "bulk_add_rules":
        bulk_add_rules(args, cookie)

if __name__ == "__main__":
    main()
