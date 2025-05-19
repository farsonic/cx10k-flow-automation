# CX10K Policy Automation & Flow Analysis Toolkit

A collection of Python tools for Pensando CX10K syslog, DC flow simulation, policy management, and security analytics—backed by Redis, with OpenAI GPT integration for flow analysis.

## Directory Contents

- **send_logs.py**
  Simulates Pensando/CX10K network flows and sends them as syslog to your collector.

- **syslog_server.py**
  A UDP syslog server ("CXLogVault") that parses, decodes, and stores flow logs in Redis, including IANA port mapping and optional OpenAI enrichment.

- **vlan_dependencies.py**
  Builds DC app dependency tables from captured flows, suggests policy/rules, generates firewall/PSM configs, and can call GPT-4 for security analysis.

- **rule_manager.py**
  CLI for creating, updating, and deleting apps, policies, rules, and IP collections in your PSM (Pensando Policy and Security Manager).

- **service-names-port-numbers.csv**
  (Auto-downloaded) IANA official port/protocol mapping.
  You do **not** need to manage or edit this file.

- **config.json**
  Local configuration file (contains API keys, PSM host, credentials, and GPT model).

---

## Setup

### 1. Install Requirements

- Python 3.7+
- `pip install redis tabulate requests openai`

### 2. Redis Server

- Run a local or remote Redis instance (`redis-server`) and ensure it's accessible at `localhost:6379` (or update scripts for your host/port).

### 3. Prepare `config.json`

Create a file called `config.json` in this directory

**Example:**
```json
{
  "psmipaddress": "192.168.0.128",
  "psmusername": "admin",
  "psmpassword": "Pensando0$",
  "session_ttl_days": 7,
  "redis_maxmemory_mb": 1024,
  "openai_api_key": "sk-...",
  "openai_model": "gpt-4o"
}
```

**Fields:**
- `psmipaddress`, `psmusername`, `psmpassword`: For policy CRUD via `rule_manager.py`
- `session_ttl_days`: Retention for flows in Redis
- `redis_maxmemory_mb`: For your Redis config (optional, see below)
- `openai_api_key`: Your OpenAI API key (required for GPT features)
- `openai_model`: OpenAI model to use (`gpt-4o`, `gpt-4`, etc.)


---

## Usage

### **1. Run Syslog Server**

```sh
python3 syslog_server.py
```
- Stores parsed session logs in Redis.
- Handles IANA port mapping.
- Supports TTL and offloading for old logs.

### **2. Simulate and Send Flows**

```sh
python3 send_logs.py --host 127.0.0.1 --port 5514 --count 5000 --rate 50
```

### **3. Build/Review DC Policy from Flows**

```sh
python3 vlan_dependencies.py
```
- Shows an interactive dependency table (default, dry-run mode).

#### **Apply to PSM (creates rules, apps, collections):**
```sh
python3 vlan_dependencies.py --apply --since 4h --policy-name my_policy
```

#### **Remove Policy or Rule:**
```sh
python3 vlan_dependencies.py --remove --policy-name my_policy
python3 vlan_dependencies.py --remove --policy-name my_policy --rule-name catch_all
```

#### **Security Analysis with GPT-4o:**
```sh
python3 vlan_dependencies.py --analyse --since 2h
```
- Prompts for the Internet VLAN and gives a detailed AI-powered security review.

#### **List VLANs / Show Redis Stats:**
```sh
python3 vlan_dependencies.py --vlan-list
python3 vlan_dependencies.py --capacity
```

### **4. Manage PSM Policies/Apps Directly**
```sh
python3 rule_manager.py create_app --name http --definitions tcp:80
python3 rule_manager.py ip_collection --add-ipcollection --name vlan10_hosts --addresses 10.10.10.2/32 10.10.10.3/32
python3 rule_manager.py create_policy --name my_policy
python3 rule_manager.py add_rule --policy_name my_policy --rule_name web_to_db --apps http --action permit --from_ip_collections vlan10_hosts --to_ip_collections vlan20_hosts
```

---

## Security Notes

- Set `maxmemory` and `maxmemory-policy` in your Redis configuration for production.
- Use a firewall and bind Redis to `127.0.0.1` (or use ACLs/tls).

---

## Questions / Issues?

Open a GitHub issue or contact the repo maintainer.

This is a proof of concept and useful for demonstration purposes.

---

**Enjoy automated CX10K flow analytics and zero-trust policy generation!**
