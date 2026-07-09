# Smart SIEM CTU — Ubuntu Version (sans Active Directory)

> **But** : Remplacer les VMs Windows (DC01 + Target Win) par **2 machines Ubuntu**
> dans le lab SIEM/SOAR existant. Pas d'Active Directory, pas de domaine.
>
> **Réseau et pfSense inchangés** : se référer au guide principal `SIEM-LAB-SETUP.md`
> pour l'infrastructure réseau, pfSense, Kali et Docker.

---

## Table des matières

1. [Plan de remplacement](#1-plan-de-remplacement)
2. [VM 2 : Ubuntu Server (ex-DC01)](#2-vm-2--ubuntu-server-ex-dc01)
3. [VM 3 : Ubuntu Desktop (ex-Target Win)](#3-vm-3--ubuntu-desktop-ex-target-win)
4. [Log Ingestion : Filebeat (remplace Winlogbeat)](#4-log-ingestion--filebeat-remplace-winlogbeat)
5. [Règles de corrélation (adaptation)](#5-règles-de-corrélation-adaptation)
6. [Attack Simulations (adaptation)](#6-attack-simulations-adaptation)
7. [Récapitulatif des changements](#7-récapitulatif-des-changements)

---

## 1. Plan de remplacement

| Ancien (Windows) | Nouveau (Ubuntu) | IP | Rôle |
|---|---|---|---|
| `dc01` — Windows Server | `ubuntu-srv` | `192.168.133.10` | Serveur Ubuntu (pas de DC) |
| `target-win` — Windows 10 | `ubuntu-target` | `192.168.133.20` | Machine cible Ubuntu |

Pas d'Active Directory, pas de domaine. Les utilisateurs sont **locaux** à chaque machine.

---

## 2. VM 2 : Ubuntu Server (ex-DC01)

### 2.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `ubuntu-srv` |
| OS | Ubuntu Server 22.04/24.04 LTS |
| Memory | 2048 MB |
| Disk | 20 GB (dynamique) |
| NIC 1 | `Host-Only (VMnet1) — LAN` |
| Audio | Disabled |
| USB | Disabled |

### 2.2 Installation

1. Boot from Ubuntu Server ISO
2. Installation :
   - Language : English
   - Network : configurer manuellement l'IP (voir 2.3)
   - Proxy : laisser vide
   - Mirror : par défaut
   - Storage : utiliser tout le disque
   - Profile :
     - Hostname : `ubuntu-srv`
     - Username : `admin`
     - Password : `P@ssw0rd123!`
   - SSH : cocher **"Install OpenSSH server"** ✅
   - Snaps : rien d'autre
3. Redémarrer

### 2.3 Network Configuration (static IP)

```bash
# Lister vos interfaces
ip a

# Créer le fichier netplan
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:   # ← remplacer par le nom trouvé avec ip a
      addresses:
        - 192.168.133.10/24
      routes:
        - to: default
          via: 192.168.133.128   # pfSense LAN
      nameservers:
        addresses:
          - 192.168.133.128
          - 1.1.1.1
```

```bash
sudo netplan apply

# Vérifications
ping 192.168.133.128   # pfSense LAN → OK
ping 192.168.133.1     # Hôte Docker → OK
```

### 2.4 Installer les services de base

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  openssh-server \
  ufw \
  htop \
  net-tools \
  curl \
  jq \
  auditd \
  rsyslog
```

### 2.5 Configurer auditd

```bash
sudo auditctl -e 1

sudo tee -a /etc/audit/rules.d/audit.rules > /dev/null << 'EOF'
-w /var/log/auth.log -p wa -k auth_logs
-w /var/log/syslog -p wa -k syslog_changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes
EOF

sudo systemctl restart auditd
sudo systemctl enable auditd
sudo auditctl -l   # vérifier
```

### 2.6 Créer des utilisateurs de test

```bash
sudo useradd -m -s /bin/bash -G sudo jmiller
echo "jmiller:Passw0rd!" | sudo chpasswd

sudo useradd -m -s /bin/bash -G sudo sconnor
echo "sconnor:Passw0rd!" | sudo chpasswd

sudo useradd -m -s /bin/bash admin.bob
echo "admin.bob:P@ssw0rd123!" | sudo chpasswd
```

### 2.7 Verification Checklist

```bash
✅ ping 192.168.133.1          → OK
✅ ping 192.168.133.128        → OK
✅ curl http://192.168.133.1:9200 → OK (Elasticsearch)
✅ getent passwd jmiller sconnor admin.bob → 3 users
✅ sudo auditctl -l            → règles actives
```

---

## 3. VM 3 : Ubuntu Desktop (ex-Target Win)

### 3.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `ubuntu-target` |
| OS | Ubuntu Desktop 22.04/24.04 LTS |
| Memory | 4096 MB |
| Disk | 40 GB (dynamique) |
| NIC 1 | `Host-Only (VMnet1) — LAN` |
| Audio | Disabled |
| USB | Disabled |

### 3.2 Installation

1. Boot from **Ubuntu Desktop** ISO
2. Installation :
   - Network : configurer l'IP manuellement (voir 3.3)
   - Hostname : `ubuntu-target`
   - Username : `admin`
   - Password : `P@ssw0rd123!`
   - Coche "Install third-party software"
3. Redémarrer

### 3.3 Network Configuration (static IP)

```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  renderer: NetworkManager   # Desktop utilise NetworkManager
  ethernets:
    ens33:
      addresses:
        - 192.168.133.20/24
      routes:
        - to: default
          via: 192.168.133.128
      nameservers:
        addresses:
          - 192.168.133.128
          - 1.1.1.1
```

```bash
sudo netplan apply

ping 192.168.133.10   # ubuntu-srv → OK
ping 192.168.133.1    # hôte Docker → OK
```

### 3.4 Installer SSH (cible de l'attaque brute force)

```bash
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

ss -tlnp | grep :22   # → LISTEN
```

### 3.5 Créer un utilisateur vulnérable

```bash
sudo useradd -m -s /bin/bash jmiller
echo "jmiller:Passw0rd!" | sudo chpasswd   # mot de passe faible
```

### 3.6 Verification Checklist

```bash
✅ ping 192.168.133.1       → OK
✅ ping 192.168.133.10      → OK
✅ curl http://192.168.133.1:9200 → OK
✅ ss -tlnp | grep :22      → SSH écoute
```

---

## 4. Log Ingestion : Filebeat (remplace Winlogbeat)

### 4.1 Installer Filebeat (sur les DEUX machines)

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install -y filebeat
```

### 4.2 Configurer Filebeat — ubuntu-srv

```bash
sudo nano /etc/filebeat/filebeat.yml
```

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
    fields:
      source_type: "linux_auth"
    fields_under_root: false

  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      source_type: "linux_auditd"
    fields_under_root: false

output.elasticsearch:
  hosts: ["192.168.133.1:9200"]
  index: "filebeat-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo filebeat test output   # → Connection OK
```

### 4.3 Configurer Filebeat — ubuntu-target

Même chose, mais avec `source_type: "linux_target"` :

```yaml
    fields:
      source_type: "linux_target"
```

---

## 5. Règles de corrélation (adaptation)

Les Event ID Windows n'existent plus. Les règles doivent chercher dans les logs textes :

| Règle | Avant (Windows) | Après (Ubuntu) |
|-------|----------------|----------------|
| **R001** Brute Force | Event ID 4625 | `Failed password for .* from 192.168.243.10` dans auth.log |
| **R002** Pass-the-Hash | Spécifique Windows | **Désactivée** ou remplacée par SSH Lateral Movement (T1021.004) |
| **R003** Exfiltration | Upload PowerShell | `scp` / `rsync` / `curl` vers IP externe |
| **R004** Log Clearing | `wevtutil cl Security` | `rm /var/log/auth.log` ou `journalctl --rotate` |
| **R005** Reconnaissance | Nmap vers Windows | Nmap vers Ubuntu (même principe) |

Dans le backend NestJS, la règle R001 doit chercher le pattern :

```
Failed password for jmiller from 192.168.243.10
```

au lieu de `event_id: 4625`.

---

## 6. Attack Simulations (adaptation)

### 6.1 Brute Force SSH (⭐ star du show)

Au lieu de RDP, on attaque le **SSH** :

```bash
# Depuis Kali
echo -e "Wrong1\nWrong2\nWrong3\nWrong4\nPassw0rd!" > /tmp/demo-passwords.txt

hydra -l jmiller -P /tmp/demo-passwords.txt ssh://192.168.133.20 -V -t 4
```

Le pipeline reste identique :
1. Filebeat capture `Failed password` dans auth.log → Elasticsearch
2. Règle R001 détecte ≥ 5 échecs → incident
3. SOAR appelle API pfSense → blocage de l'IP Kali

### 6.2 Autres attaques

| # | Attaque | Commande | Règle |
|---|---------|----------|-------|
| 1 | Brute Force SSH | `hydra -l jmiller ... ssh://192.168.133.20` | **R001** |
| 2 | Reconnaissance | `nmap -sS 192.168.133.20 -p 1-10000` | **R005** |
| 3 | Log Clearing | `ssh admin@192.168.133.20 'sudo rm -f /var/log/auth.log'` | **R004** + SOAR |
| 4 | Exfiltration | `scp ~/largefile.bin admin@192.168.133.10:/tmp/` | **R003** |

---

## 7. Récapitulatif des changements

| Aspect | Windows (avant) | Ubuntu (après) |
|--------|----------------|----------------|
| **OS ubuntu-srv** | Windows Server 2022 | Ubuntu Server 22.04/24.04 |
| **OS ubuntu-target** | Windows 10 Pro | Ubuntu Desktop 22.04/24.04 |
| **Domaine** | `smart-siem.lab` (AD) | Pas de domaine, users locaux |
| **Service attaqué** | RDP (port 3389) | **SSH (port 22)** |
| **Outil brute force** | `hydra ... rdp://` | `hydra ... ssh://` |
| **Log shipper** | Winlogbeat | **Filebeat** |
| **Format logs** | Event IDs Windows | Fichiers texte (auth.log, audit.log) |
| **Audit** | auditpol (Windows) | **auditd** (Linux) |
| **Config réseau** | PowerShell | **Netplan** (YAML) |
| **Stockage total** | ~96 Go | ~60 Go |
| **RAM totale (VMs)** | ~2.7 Go | ~2.5 Go |

> **Version** : 1.0
> **Basé sur** : `SIEM-LAB-SETUP.md` — Smart SIEM CTU
> **Date** : 2026-07-09
