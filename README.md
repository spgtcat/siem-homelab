# SIEM Homelab — Cyber Attack Simulation & Log Analysis (SOC Lab)

**Author:** Emran
**Project type:** Self-built home lab / Blue Team security project
**Stack:** Proxmox VE · Wazuh 4.14 (Indexer / Manager / Dashboard) · Kali Linux · Debian
**Focus:** Detection, log analysis, and attack simulation in a closed lab

---

## 1. Summary

I built a full SIEM environment from scratch. SIEM means Security Information and Event Management — a system that collects logs and detects attacks. I used it to simulate a real attack and detect it.

The lab runs on an old laptop. I turned it into a server with Proxmox. On that server I run three machines: the SIEM, a victim, and an attacker.

My goal was not just to install a tool. I wanted to understand the full path of an attack. How an attack makes events. How those events go from the victim to the SIEM. How the SIEM turns events into alerts. And how a SOC analyst reads those alerts.
![image alt](https://github.com/spgtcat/siem-homelab/blob/96bd44a532e208600d7c77a4628f247294689f51/Screenshot%202026-06-07%20183628.png)
I tested three types of detection in one attack story:

1. **Log-based detection** — SSH brute force
2. **Correlation-based detection** — a login that works after many failed tries (a hacked account)
3. **File-based detection** — a web shell dropped on a web server

> **Honest note:** The first build did not work. I got stuck on the security setup of the Wazuh Indexer. The problem was the TLS certificates. Instead of forcing a fix, I deleted everything and built it again the clean way. I wrote this part down on purpose. Finding the problem and fixing it the right way is an important security skill.

---

## 2. Lab Architecture

The whole lab runs on one Proxmox server (the old laptop). I manage it from my own PC through the browser.

| Role | Hostname | IP | What it does |
|------|----------|-----|--------------|
| **SIEM server** | `wazuh-siem` | `192.168.2.90` | Wazuh Indexer + Manager + Dashboard |
| **Victim** | `debian` | `192.168.2.87` | The monitored machine: Wazuh agent, SSH, Apache/PHP |
| **Attacker** | `kali` | `192.168.2.88` | Kali Linux — I run all attacks from here |

**How the data moves:**

```
[Kali attacker] --attack--> [Debian victim]
                                   |
                          (Wazuh agent collects events)
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

> *[Screenshot: Proxmox dashboard with the wazuh-siem container and the VM list]*

### How the parts work together

- The **agent** on the victim only collects events. It does not have the detection rules.
- The **Manager** has the rules. This is where events become alerts.
- **Filebeat** sends the alerts to the Indexer over TLS (a secure connection).
- The **Indexer** stores everything. The **Dashboard** shows it.

---

## 3. How I Built It

### 3.1 Setting up the host (an LXC problem)

The SIEM runs inside an LXC container. The Indexer needs a kernel setting called `vm.max_map_count`. In an LXC container you must set this on the Proxmox host, not inside the container:

```bash
# On the Proxmox host
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
```

Without this, the Indexer does not start. I checked the value inside the container too, to be sure it worked.

### 3.2 Certificates (the clean way)

This was the most important lesson. Wazuh uses TLS certificates to keep the connection between its parts safe. I made all certificates at once with the official tool `wazuh-certs-tool.sh`. I used one config file with all three machines:

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

This made a separate certificate for the indexer, the server, the dashboard, and a special admin certificate. All were signed by the same root CA. Making them all at once is what fixed the problem from my first try.

> *[Screenshot: wazuh-certs-tool.sh making all the certificates]*

### 3.3 Installing the parts

I installed each part step by step from the official Wazuh repo (version 4.14.5):

1. **Indexer** — installed, added the certificates, started the security with `indexer-security-init.sh`. The cluster health was `green`.
2. **Manager + Filebeat** — installed. I set up Filebeat with the server certificate. The password is in the keystore, not in plain text. I tested the connection with `filebeat test output`.
3. **Dashboard** — installed and connected to the Indexer (for data) and the Manager API (to manage agents).

> *[Screenshot: `filebeat test output` showing handshake OK and talk to server OK]*
> *[Screenshot: Wazuh Dashboard after the first login]*

### 3.4 Installing the agent

I installed the Wazuh agent on the Debian victim. It registered with the Manager by itself. The status was `Active`:

```bash
# On the Manager
/var/ossec/bin/agent_control -l
#   ID: 001, Name: debian, IP: any, Active
```

> *[Screenshot: agent_control -l showing debian as Active]*

---

## 4. Attacks and Detections

I ran all attacks from the Kali machine (`192.168.2.88`) against the Debian victim (`192.168.2.87`). This is my own closed lab. I did everything on machines I own.

### Phase 1 — SSH Brute Force (log-based)

**Attack (from Kali):**
```bash
hydra -l emran -P /tmp/passwords.txt ssh://192.168.2.87 -t 4 -V
```
Hydra tried many passwords on the SSH service.

**What Wazuh saw:**

Wazuh did not just log each failed try. It linked them together and raised the level. Single failed logins (level 5) became a higher alert:

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5760 | sshd: authentication failed | 5 |
| 2501 | syslog: user authentication failure | 5 |
| 5758 | Maximum authentication attempts exceeded | 8 |
| 2502 | User missed the password more than one time | 10 |
| **40111** | **Multiple authentication failures** | **10** |

> *[Screenshot: Threat Hunting dashboard with about 282 failed logins and the attack spike]*
> *[Screenshot: Events view showing the level go from 5 to 10, all from IP 192.168.2.88]*

**How an analyst reads this:** The key alert is rule **40111**. This is the linked alert, not one single failed login. Wazuh saw many failed tries from one IP and decided it was an attack. I added `data.srcip` as a column. All the failed tries came from one IP (`192.168.2.88`). This shows it was a real attack, not a user who forgot their password. **MITRE ATT&CK: T1110 (Brute Force).**

### Phase 2 — Successful Break-In (correlation-based)

**Attack (from Kali):** I added a weak password (`password123`) to the list. It is in the rockyou wordlist at line 1384. Hydra then cracked the account:

```
[22][ssh] host: 192.168.2.87   login: emran   password: password123
1 of 1 target successfully completed, 1 valid password found
```

After I got in, I logged in as the hacked account and did normal attacker actions:

```bash
whoami; id; uname -a; cat /etc/passwd     # looking around
sudo cat /etc/shadow                       # trying to get root (blocked)
```

**What Wazuh saw:**

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5715 | sshd: authentication success | 3 |
| **40112** | **Multiple authentication failures followed by a success** | **12** |

> *[Screenshot: Hydra output showing the cracked password (green line)]*
> *[Screenshot: Events view with rule 40112, level 12, "failures followed by a success", IP 192.168.2.88]*

**How an analyst reads this:** This is the strongest alert in the project. Rule **40112** links the failed tries with the login that worked, all from the same IP. It goes up to **level 12**. This is the clear sign of a hacked account. One good login on its own can be normal. But a good login right after many failed tries from the same IP is a problem. The "looking around" commands (`whoami`, `cat /etc/passwd`) did not make alerts. That is a good lesson: not everything an attacker does is detected by default. The try to read `/etc/shadow` did make an alert. **MITRE ATT&CK: T1110 -> T1078 (Valid Accounts).**

### Phase 3 — Web Shell (file-based, real-time)

To show a different kind of detection, I installed Apache + PHP on the victim. Then I turned on real-time File Integrity Monitoring (FIM) on the web folder:

```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
```

**Attack:** I put a PHP web shell in the web folder:

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

> *[Screenshot: Events view with rule 554 "File added to the system" for /var/www/html/shell.php]*
> *[Screenshot: the open alert showing the file path and the file content]*

**How an analyst reads this:** This is a different kind of detection from Phase 1 and 2. It does not read logs. FIM watches the files in real time. It makes an alert the moment a file is added or changed in a watched folder. Because I turned on `report_changes`, the alert shows the bad PHP code itself. On a web server, a new `.php` file that you did not put there is a strong sign of a web shell. A web shell lets an attacker run commands from far away. **MITRE ATT&CK: T1505.003 (Web Shell).**

---

## 5. The Full Attack Chain

All three phases together make one real attack story. This is how a real break-in happens. I can follow all of it on one timeline by the source IP:

```
1. Brute force        (T1110)        -> many failed SSH logins        [rule 40111, level 10]
2. Break-in           (T1078)        -> weak password cracked          [rule 40112, level 12]
3. Looking around     (T1082/T1087)  -> system & account discovery     [partly detected]
4. Try to get root    (T1548)        -> tried to read /etc/shadow      [detected]
5. Web shell          (T1505.003)    -> bad file dropped in web folder [rule 554/550]
```

---

## 6. Problems and Lessons

**The certificate problem.** My first build failed many times. I kept getting the error `"... is not an admin user"` when I tried to start the Indexer security. The connection worked, but it would not give me admin rights. The reason: I used the node certificate as the admin certificate. OpenSearch has a hard rule. A certificate that is a node can never be an admin. This is on purpose. It stops a hacked node from taking over the cluster. You cannot fix this by editing the config. You need a separate admin certificate.

**The fix.** I did not keep patching the broken setup. I deleted everything and built it again the clean way. I made all certificates at once with the official tool. The clean build worked on the first try — `Done with success` — with no error.

**What I learned:**

- A SIEM is only as safe as its setup. It is better to understand *why* a security control blocks you than to force your way past it.
- Detection has layers: raw events -> linked alerts -> higher level. The linked alerts (40111, 40112) are the smart part.
- Not everything is detected by default. Knowing the gaps is a SOC skill too.
- A clean rebuild is often faster and safer than fixing a broken setup.

---

## 7. What I Could Add Next

- **Custom rules** — a rule in `local_rules.xml` that knows web-shell code (`system(`, `$_GET`, `eval(`) and makes it critical (level 13+), mapped to MITRE T1505.003. This is detection engineering: tuning the SIEM to the threat.
- **auditd** — logs every command, so "looking around" is also detected.
- **Active Response** — block an attacker's IP by itself with `firewall-drop`.
- **Sysmon + a Windows machine** — more detailed logs and more attack types.
- **Change default passwords** — rotate the default `admin` password with the Wazuh passwords tool. The lab is on a closed network with no outside access.

---

## 8. Skills I Showed

- Building and setting up a full SIEM stack (Wazuh Indexer, Manager, Dashboard) from scratch
- Working with TLS certificates to secure the connection between parts
- Linux server admin (Debian, systemd services, packages)
- Installing agents and monitoring a machine
- Running attacks with real tools (Hydra, Kali Linux)
- Reading logs, sorting alerts, and understanding linked alerts
- Mapping detections to the MITRE ATT&CK framework
- Finding problems and fixing them the clean way

---

*I built and ran this lab only on my own machines, on a closed network, to learn.*
