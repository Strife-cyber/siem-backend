# Smart SIEM CTU — Enterprise Lab & SOAR Demonstration Guide

> **Document Purpose**: Step-by-step instructions to build a 4-VM enterprise network
> on **VMware + Docker Desktop (Windows)**, simulate MITRE ATT&CK techniques,
> trigger Smart SIEM correlation rules, and verify SOAR playbook execution — all
> for a live jury demonstration.
>
> **SOAR Firewall Provider**: pfSense (the default for this lab)
> **Environment Variable**: `SOAR_FIREWALL_PROVIDER=pfsense`
> **Host OS**: Windows 10/11 with Docker Desktop

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Hardware Requirements](#2-hardware-requirements)
3. [Network Topology & IP Plan](#3-network-topology--ip-plan)
4. [VMware VM Setup — General](#4-vmware-vm-setup--general)
5. [VM 1: pfSense Firewall](#5-vm-1-pfsense-firewall)
6. [VM 2: Windows Server — Domain Controller](#6-vm-2-windows-server--domain-controller)
7. [VM 3: Windows 10 — Target Workstation](#7-vm-3-windows-10--target-workstation)
8. [VM 4: Kali Linux — Attacker](#8-vm-4-kali-linux--attacker)
9. [Docker Desktop — SIEM & Dependencies](#9-docker-desktop--siem--dependencies)
10. [SIEM Application Configuration](#10-siem-application-configuration)
11. [Log Ingestion Pipeline](#11-log-ingestion-pipeline)
12. [MITRE ATT&CK — Correlation Rules](#12-mitre-attck--correlation-rules)
13. [Attack Simulations — Step by Step](#13-attack-simulations--step-by-step)
14. [SOAR Playbook Verification](#14-soar-playbook-verification)
15. [Jury Demo Script](#15-jury-demo-script)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  YOUR WINDOWS PC                                                     │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Docker Desktop                                                  │ │
│  │  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐ │ │
│  │  │ NestJS    │  │            │  │          │  │              │ │ │
│  │  │ Backend   │  │ Elastic    │  │ Postgres │  │ Redis +      │ │ │
│  │  │ (SOAR)    │  │ search     │  │          │  │ syslog-ng    │ │ │
│  │  └──────────┘  └────────────┘  └──────────┘  └──────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────── VMware ─────────────────────────────────┐ │
│  │                                                                  │ │
│  │  ┌──────────────────────────┐      ┌──────────────────────────┐│ │
│  │  │  Kali Linux              │      │  pfSense                 ││ │
│  │  │  (Attacker)              │      │  (Firewall)              ││ │
│  │  │  192.168.243.10              │      │  WAN: 192.168.243.128          ││ │
│  │  │                          │      │  LAN: 192.168.133.128          ││ │
│  │  └──────────────────────────┘      └──────────┬───────────────┘│ │
│  │              │ WAN (NAT Network)              │ LAN (Host-Only) │ │
│  │              └────────────────────────────────┼────────────────┘ │
│  │                                                │                 │
│  │                 ┌──────────────────────────────┼──────────────┐  │
│  │                 │              ┌───────────────▼───────────┐  │  │
│  │                 │              │  Windows Server Core      │  │  │
│  │                 │              │  (Domain Controller)      │  │  │
│  │                 │              │  192.168.133.10               │  │  │
│  │                 │              │  + Winlogbeat             │  │  │
│  │                 │              └───────────────────────────┘  │  │
│  │                 │                                              │  │
│  │                 │              ┌───────────────────────────┐  │  │
│  │                 │              │  Windows 10 Pro           │  │  │
│  │                 │              │  (Target Workstation)     │  │  │
│  │                 │              │  192.168.133.20               │  │  │
│  │                 │              │  + Winlogbeat + RDP       │  │  │
│  │                 │              └───────────────────────────┘  │  │
│  │                 └─────────────────────────────────────────────┘  │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘

Network Segments:
  WAN  (VMware NAT - VMnet8):     192.168.243.0/24  → Kali + pfSense WAN (internet via NAT)
  LAN  (VMware Host-Only - VMnet1): 192.168.133.0/24  → All VMs + Windows Host (Docker)
  Host LAN IP:                       192.168.133.1     → Docker services accessible here
```

### Traffic Flow for Attacks

```
Kali (192.168.243.10)
  │
  │ Attack traffic (RDP, SMB, Nmap...)
  ▼
pfSense WAN (192.168.243.128)
  │
  │ ── blocks malicious traffic when SOAR fires
  │ ── logs everything (syslog → SIEM on host)
  ▼
pfSense LAN (192.168.133.128)
  │
  ├── DC Server (192.168.133.10)     → Winlogbeat → Elasticsearch (host:9200)
  ├── Target Win (192.168.133.20)    → Winlogbeat → Elasticsearch (host:9200)
  └── Your Windows Host (192.168.133.1) ← Docker: SIEM, ES, Postgres, Redis
                                       ← SOAR calls pfSense API on 192.168.133.128
```

---

## 2. Hardware Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 6+ cores, virtualization enabled (VT-x / AMD-V) |
| RAM | 16 GB minimum, 32 GB recommended |
| Storage | 256 GB SSD free space |
| OS | Windows 10 Pro or Windows 11 |
| Software | Docker Desktop + VMware Workstation/Player |

### Measured Resource Usage at Idle

| VM / Service | RAM | Disk |
|---|---|---|
| pfSense CE (1 vCPU) | ~350 MB | 8 GB |
| Windows Server Core (2 vCPU) | ~900 MB | 32 GB |
| Windows 10 Pro (2 vCPU) | ~1.8 GB | 64 GB |
| Kali Linux (2 vCPU) | ~500 MB | 30 GB |
| Docker (ES + Postgres + Redis + Backend) | ~3 GB | ~15 GB |

**Total**: ~6.5 GB RAM VMs + ~3 GB Docker = ~10 GB under load.

---

## 3. Network Topology & IP Plan

### Required VMware Networks (create these FIRST)

| Network | Type | Subnet | DHCP | Purpose |
|---------|------|--------|------|---------|
| `WAN` | NAT Network | 192.168.243.0/24 | DISABLED | Kali + pfSense WAN |
| `LAN` | Host-Only | 192.168.133.0/24 | DISABLED | All LAN VMs + Windows host |

### Create "WAN" NAT Network

VMware's default NAT network (VMnet8) usually uses `192.168.xxx.0/24`. To ensure it matches our lab:

1. Open **VMware Workstation → Edit → Virtual Network Editor** (run as admin)
2. Find **VMnet8 (NAT)** — select it
3. Click **Change Settings** (bottom right)
4. Select **VMnet8** again
5. Set **Subnet IP**: `192.168.243.0` and **Subnet mask**: `255.255.255.0`
6. Click **NAT Settings** — note the Gateway IP (usually `192.168.243.2`)
7. **Uncheck** DHCP if you want everything static (optional — Kali can also use DHCP)
8. Click OK

### Create "LAN" Host-Only Network

1. In the same **Virtual Network Editor** → **Add Network...**
2. Select **VMnet1 (Host-Only)** or create a new one
3. Set **Subnet IP**: `192.168.133.0` and **Subnet mask**: `255.255.255.0`
4. **Uncheck** DHCP (pfSense will be DHCP server instead)
5. Click OK

> **Why Host-Only?** The Windows host automatically gets 192.168.133.1, so Docker
> services (Elasticsearch :9200, Backend :3000) are reachable from all VMs.
> No separate SIEM VM needed.

### Static IP Assignments

All IPs are configured manually inside each OS after installation.

| Hostname | Network | IP | Gateway | DNS | Notes |
|----------|---------|----|---------|-----|-------|
| **pfsense** WAN | WAN | 192.168.243.128/24 | — | — | pfSense WAN interface |
| **pfsense** LAN | LAN | 192.168.133.128/24 | — | — | pfSense LAN interface (.2, not .1!) |
| **dc01** | LAN | 192.168.133.10/24 | 192.168.133.128 | 192.168.133.10 | Domain Controller + DNS |
| **target-win** | LAN | 192.168.133.20/24 | 192.168.133.128 | 192.168.133.10 | Domain-joined workstation |
| **kali** | WAN | 192.168.243.10/24 | 192.168.243.128 | 1.1.1.1 | Attacker (untrusted side) |
| **Windows Host** | LAN | 192.168.133.1/24 | — | — | Docker SIEM lives here |

### NIC Assignment Per VM

| VM | Adapter 1 | Adapter 2 |
|----|-----------|-----------|
| **pfSense** | NAT (VMnet8) — WAN → em0 | Host-Only (VMnet1) — LAN → em1 |
| **Kali** | NAT (VMnet8) — WAN → eth0 | — |
| **DC Server** | Host-Only (VMnet1) — LAN → eth0 | — |
| **Target Win** | Host-Only (VMnet1) — LAN → eth0 | — |

> Adapter names em0/em1 (pfSense) and eth0 (Linux/Windows) are OS-level,
> not hypervisor-specific — same regardless of VMware or VirtualBox.

---

## 4. VMware VM Setup — General

### 4.1 What You Need

```powershell
# 1. Download and install VMware Workstation Pro or VMware Workstation Player
#    https://www.vmware.com/products/workstation-pro.html

# 2. Download OS ISOs (save to a folder, no USB needed):
#    - pfSense-CE-2.7.2-RELEASE-amd64.iso
#    - Windows Server 2022/2016 Evaluation (Microsoft site)
#    - Windows 10 Pro ISO (Microsoft site)
#    - kali-linux-2024.1-installer-amd64.iso
```

### 4.2 Common VM Settings

When creating a VM, use these as a base:

| Setting | pfSense | Windows VMs | Kali |
|---------|---------|-------------|------|
| Guest OS | BSD → FreeBSD (64-bit) | Microsoft Windows → Windows 10/2022 | Linux → Debian (64-bit) |
| Firmware | BIOS (no UEFI) | UEFI | Default |
| Virtualization | VT-x + Nested Paging | VT-x + Nested Paging | VT-x + Nested Paging |

### 4.3 Attaching ISOs

```
VM Settings → CD/DVD (SATA) → Use ISO image file → Browse
  → Select the .iso from your Downloads folder

Ensure "Connect at power on" is checked.
After OS install: Settings → CD/DVD → Remove ISO or set to "Use physical drive".
```

---

## 5. VM 1: pfSense Firewall

### 5.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `pfsense` |
| Memory | 1024 MB |
| Disk | 8 GB (VMware virtual disk, dynamically allocated) |
| NIC 1 | `NAT (VMnet8) — WAN` |
| NIC 2 | `Host-Only (VMnet1) — LAN` |
| NIC type (both) | **Intel PRO/1000 MT Desktop (e1000)** |
| Audio | Disabled |
| USB | Disabled |

> pfSense's FreeBSD kernel has issues with VMXNET3 NICs. Always use **e1000**.
> VMware's default for FreeBSD guests is e1000 — just verify it's selected.

### 5.2 Installation

1. Boot from pfSense ISO
2. Accept all defaults (US keymap, quick install)
3. Let the installer complete, then remove the ISO and reboot
4. Accept the license agreement

### 5.3 Interface & IP Configuration (Console)

```
Option 1) Assign Interfaces:
  WAN  = em0  (matches NIC 1 — NAT Network)
  LAN  = em1  (matches NIC 2 — Host-Only)
  Do both interfaces use DHCP? → NO for both
  Proceed.

Option 2) Set Interface IPs:

  WAN (em0):
    IPv4: 192.168.243.128/24
    IPv4 Gateway: 192.168.243.2   // VMware NAT gateway (for internet access)
    Disable IPv6: y

  LAN (em1):
    IPv4: 192.168.133.128/24    ← .128 because Windows host already uses .1
    IPv4 Gateway: NONE
    Disable IPv6: y
```

### 5.4 Web UI Configuration

Open http://192.168.133.128 from your Windows browser.

Login: `admin` / `pfsense`

#### WAN Interface (Interfaces → WAN)

| Setting | Value |
|---------|-------|
| IPv4 Configuration | Static |
| IPv4 Address | 192.168.243.128/24 |
| Block private networks | **UNCHECKED** |
| Block bogon networks | **UNCHECKED** |

#### LAN Interface (Interfaces → LAN)

| Setting | Value |
|---------|-------|
| IPv4 Configuration | Static |
| IPv4 Address | 192.168.133.128/24 |

#### DHCP Server for LAN (Services → DHCP Server → LAN)

| Setting | Value |
|---------|-------|
| Enable | ✅ |
| Range | 192.168.133.100 - 192.168.133.200 |
| DNS Servers | 192.168.133.10 (DC) |
| Gateway | 192.168.133.128 |

#### DNS Resolver (Services → DNS Resolver)

- Enable Forwarding Mode: ✅
- DNS Servers: 1.1.1.1, 8.8.8.8

#### Firewall Rules

> **WARNING**: Do NOT create any "allow all" rules on WAN.
> Only specific pass rules for attack simulations.

**WAN**: Default deny-all (no rules = all inbound blocked)  
**LAN**: Default allow-all (LAN net → any)

### 5.5 REST API Setup (CRITICAL — required for SOAR)

```bash
pfSense Web UI → System → Package Manager → Available Packages
  Install: "pfSense-restapi" by jaredhendrickson

After install:
  Services → REST API → Settings
    Auth Mode: API Token
    Generate a token with read/write access

  Copy the API key immediately — it's shown once.
```

**Verify from Windows (PowerShell or Git Bash):**

```bash
curl -s -H "X-API-Key: YOUR_API_KEY" http://192.168.133.128/api/v2/system/info
# Expected: {"status":"ok","data":{"version":"2.7.2",...}}
```

### 5.6 Syslog to SIEM (Status → System Logs → Settings)

| Setting | Value |
|---------|-------|
| Enable Remote Logging | ✅ |
| Remote Log Server 1 | 192.168.133.1:514 |
| Log firewall events | ✅ |

### 5.7 Verification Checklist

```
✅ Web UI at http://192.168.133.128 from Windows browser
✅ WAN IP: 192.168.243.128/24
✅ LAN IP: 192.168.133.128/24
✅ Kali can ping 192.168.243.128 (pfSense WAN)
✅ Kali CANNOT ping 192.168.133.x (blocked by default)
✅ REST API responds: curl -H "X-API-Key: ..." http://192.168.133.128/api/v2/system/info
✅ Windows host can ping 192.168.133.128
✅ Syslog sending to 192.168.133.1:514
```

---

## 6. VM 2: Windows Server — Domain Controller

### 6.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `dc01` |
| Memory | 2048 MB |
| Disk | 32 GB (VMware virtual disk, dynamically allocated) |
| NIC 1 | `Host-Only (VMnet1) — LAN` (use default adapter type) |
| Audio | Disabled |
| USB | Disabled |

### 6.2 Installation

1. Boot from Windows Server 2022/2016 ISO
2. Install **Windows Server 2022 Standard (Desktop Experience)** (or Server 2016 equivalent)
3. Custom install, create partition

### 6.3 VMware Tools

```
VM → Install VMware Tools...
This mounts a virtual CD in the VM.
Open the CD in File Explorer → Run setup64.exe
Restart.
```

### 6.4 Network Configuration

```powershell
Control Panel → Network and Sharing Center → Change adapter settings:
  IPv4: 192.168.133.10/24
  Gateway: 192.168.133.128    ← pfSense LAN
  DNS: 127.0.0.1        ← will serve DNS after AD install

System Properties → Computer Name → Change → "DC01" → Restart
```

### 6.5 Install Active Directory

> **⚠️ Prerequisite**: The local Administrator account MUST have a strong password
> before promoting to a Domain Controller. If the password is empty or weak,
> `Install-ADDSForest` will fail with:
> `"Échec de la vérification des conditions préalables — le mot de passe du compte
> d'administrateur local ne répond pas aux exigences"`
>
> **Fix**: Run this first (adjust username for your language — see note below):
> ```powershell
> net user Administrator "P@ssw0rd123!"
> ```
>
> ⚠️ **Language note**: On non-English Windows installs, the local admin name
> differs (e.g. French = `Administrateur`, Spanish = `Administrador`, German =
> `Administrator`). Find the exact name with:
> ```powershell
> net user
> ```
>
> The warnings below are **normal** and can be ignored:
> - *"Autoriser les algorithmes de chiffrement compatibles avec Windows NT 4.0"*
>   — standard security notice
> - *"Impossible de créer une délégation pour ce serveur DNS"* — expected when
>   there's no parent DNS zone above `smart-siem.lab`

```powershell
# Run as Administrator:

# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
  -DomainName "smart-siem.lab" `
  -DomainNetbiosName "SMART-SIEM" `
  -ForestMode "WinThreshold" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Force:$true

# Reboots automatically. After reboot, log in as SMART-SIEM\Administrator
```

### 6.6 Create Test Users

```powershell
New-ADOrganizationalUnit -Name "Employees" -Path "DC=smart-siem,DC=lab"

$users = @(
    @{Name="John Miller"; Sam="jmiller"; Pass="Passw0rd!"},
    @{Name="Sarah Connor"; Sam="sconnor"; Pass="Passw0rd!"},
    @{Name="Admin Bob"; Sam="admin.bob"; Pass="P@ssw0rd123!"}
)

foreach ($u in $users) {
    New-ADUser -Name $u.Name -SamAccountName $u.Sam `
        -UserPrincipalName "$($u.Sam)@smart-siem.lab" `
        -Path "OU=Employees,DC=smart-siem,DC=lab" `
        -AccountPassword (ConvertTo-SecureString $u.Pass -AsPlainText -Force) `
        -Enabled:$true -PassThru
}

Add-ADGroupMember -Identity "Domain Admins" -Members "admin.bob"
```

> ⚠️ **Language note**: On non-English Windows, the "Domain Admins" group name
> is localized. **Common names found during testing:**
> - French (Windows Server 2016): `Admins du domaine`
> - French (Windows Server 2022): `Administrateurs du domaine`
>
> Always check the exact name with:
> ```powershell
> Get-ADGroup -Filter * | Select Name
> ```
> Example error if wrong: `Impossible de trouver un objet avec l'identité "..."`

### 6.7 Audit Policy (required for correlation rules)

**English (default):**

```powershell
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
```

> ⚠️ **Language note**: On non-English Windows, the subcategory names must be
> in the local language. However, localized names containing apostrophes or
> special characters may fail with `L'erreur 0x00000057 s'est produite`.
>
> **Option A — Find the exact French names:**
> ```powershell
> auditpol /list /subcategory:*
> ```
> Then set them **one at a time** (auditpol accepts only one command per line).
>
> **Option B — Use GUIDs (works in ALL languages, recommended):**
> ```powershell
> auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
> auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
> auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
> auditpol /set /subcategory:"{0CCE9249-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
> ```
> Run each GUID command **one at a time** — don't paste all at once.

### 6.8 Verification Checklist

```powershell
✅ Resolve-DnsName smart-siem.lab
✅ Get-ADUser -Filter * | ft Name
✅ auditpol /get /category:"Account Logon"     # English
   auditpol /get /category:"Connexion de compte"  # French
   # Should show: Success and Failure for "Credential Validation"
```

---

## 7. VM 3: Windows 10 — Target Workstation

### 7.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `target-win` |
| Memory | 4096 MB |
| Disk | 64 GB (VMware virtual disk, dynamically allocated) |
| NIC 1 | `Host-Only (VMnet1) — LAN` |
| Audio | Disabled |
| USB | Disabled |

### 7.2 Installation

1. Install Windows 10 **Pro** (Home can't domain-join)
2. Create a local user, finish OOBE
3. Install VMware Tools (same as DC01)
4. Enable virtualization in BIOS if needed

### 7.3 Network & Domain Join

```powershell
# Run PowerShell as Administrator

# Static IP
New-NetIPAddress -InterfaceAlias "Ethernet" `
  -IPAddress 192.168.133.20 -PrefixLength 24 -DefaultGateway 192.168.133.128

Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.133.10

Rename-Computer -NewName "TARGET-WIN" -Restart

# After reboot:
Add-Computer -DomainName "smart-siem.lab" `
  -Credential (Get-Credential "SMART-SIEM\admin.bob") -Restart
```

### 7.4 Enable RDP (for brute force attack)

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

### 7.5 Verification Checklist

```
✅ (Get-WmiObject Win32_ComputerSystem).PartOfDomain → True
✅ Test-NetConnection -ComputerName 192.168.133.1 -Port 9200 → True (Elasticsearch)
✅ netstat -an | findstr ":3389" → LISTENING
```

---

## 8. VM 4: Kali Linux — Attacker

### 8.1 VM Settings

| Setting | Value |
|---------|-------|
| Name | `kali` |
| Memory | 2048 MB |
| Disk | 30 GB (VDI, dynamically allocated) |
| NIC 1 | `NAT Network: WAN` |
| Audio | Disabled |
| USB | Disabled |

### 8.2 Installation

1. Boot from Kali Linux ISO
2. Install with defaults, full desktop environment
3. Guest Additions not required (SSH is enough)

### 8.3 Network Configuration

```bash
# Kali auto-configures via DHCP from the VMware NAT network
# But we need a STATIC IP:

sudo tee /etc/NetworkManager/system-connections/WAN.nmconnection << 'EOF'
[connection]
id=WAN
type=ethernet
interface-name=eth0
autoconnect=true

[ipv4]
method=manual
addresses=192.168.243.10/24
gateway=192.168.243.128
dns=1.1.1.1;8.8.8.8;
EOF

sudo systemctl restart NetworkManager

# Verify
ping 192.168.243.128      # → should work (pfSense WAN)
ping 192.168.133.10     # → should FAIL (blocked by pfSense)
```

### 8.4 Install Tools

```bash
sudo apt update
sudo apt install -y hydra nmap xfreerdp2-x11
```

### 8.5 Verification Checklist

```
✅ ping 192.168.243.128    → success
✅ ping 192.168.133.10   → FAIL (blocked by pfSense)
✅ which hydra nmap  → tools installed
```

> Before each attack, you'll add a temporary pfSense WAN rule to allow
> Kali → LAN traffic. This lets the SIEM detect the attack and SOAR
> automatically BLOCK it. The blocking is the demo.

---

## 9. Docker Desktop — SIEM & Dependencies

**No SIEM VM.** All backend services run in Docker on your Windows host,
accessible from VMs at **192.168.133.1** (your Host-Only adapter IP).

### 9.1 Install Docker Desktop

```powershell
# 1. Download Docker Desktop from docker.com
# 2. During install: select "WSL 2 backend"
# 3. Restart Windows when prompted
# 4. Start Docker Desktop from Start Menu
# 5. Verify:
docker --version
docker compose version
```

### 9.2 Clone the Repository

```powershell
cd C:\Dev
git clone https://github.com/your-org/siem-backend.git
# or copy your existing project folder here
```

### 9.3 Infrastructure Docker Compose

Create `docker-compose.infra.yml` in the project root:

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "0.0.0.0:9200:9200"    # ← VMs reach ES here
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped

  postgresql:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: siem
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem_password
    ports:
      - "0.0.0.0:5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "0.0.0.0:6379:6379"
    restart: unless-stopped

  syslog-ng:
    image: balabit/syslog-ng:latest
    ports:
      - "0.0.0.0:514:514/udp"
    restart: unless-stopped

volumes:
  es_data:
  pg_data:
```

> ⚠️ **Port binding `0.0.0.0:9200:9200`** — the `0.0.0.0` part makes
> Elasticsearch reachable from your VMs at `192.168.133.1:9200`.
> Without it, Docker binds only to `127.0.0.1` (Windows localhost only).

### 9.4 Environment Variables

Create `.env` in the project root:

```env
DATABASE_URL=postgresql://siem:siem_password@localhost:5432/siem
ELASTICSEARCH_URL=http://localhost:9200
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET=your-256-bit-secret

SOAR_FIREWALL_PROVIDER=pfsense
PFSENSE_URL=http://192.168.133.128
PFSENSE_API_KEY=your-generated-api-key-here
PFSENSE_TIMEOUT=10000

# These IPs can NEVER be blocked by SOAR:
SOAR_FIREWALL_PROTECTED_IPS=192.168.133.10,192.168.133.20
HOST_IP=192.168.133.1

ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123
```

### 9.5 Build & Start

```powershell
cd C:\Dev\siem-backend

# 1. Start infrastructure
docker compose -f docker-compose.infra.yml up -d

# 2. Verify Elasticsearch
curl http://localhost:9200

# 3. Build the backend image
docker build -t siem-backend .

# 4. Run migrations
docker run --rm --network host -v ${PWD}\prisma:/usr/src/app/prisma siem-backend npx prisma migrate deploy

# 5. Seed rules
docker run --rm --network host -v ${PWD}\prisma:/usr/src/app/prisma siem-backend npx prisma db seed

# 6. Start backend
docker run -d --name siem-backend --network host --env-file .env --restart unless-stopped siem-backend

# 7. Verify
curl http://localhost:3000/api/v1/
curl http://localhost:3000/api/v1/soar/health    # ← should show pfSense connected
```

### 9.6 Windows Firewall — Allow VM Traffic

```powershell
# Run PowerShell as Administrator:

New-NetFirewallRule -DisplayName "Docker ES from VMs" `
  -Direction Inbound -Protocol TCP -LocalPort 9200 -RemoteAddress 192.168.133.0/24 -Action Allow

New-NetFirewallRule -DisplayName "Docker Backend from VMs" `
  -Direction Inbound -Protocol TCP -LocalPort 3000 -RemoteAddress 192.168.133.0/24 -Action Allow

New-NetFirewallRule -DisplayName "Docker Syslog from pfSense" `
  -Direction Inbound -Protocol UDP -LocalPort 514 -RemoteAddress 192.168.133.128 -Action Allow
```

### 9.7 Verification Checklist

```powershell
curl http://localhost:3000/api/v1/           # → Backend OK
curl http://localhost:9200                    # → ES OK
curl http://localhost:3000/api/v1/soar/health # → pfSense reachable
curl http://localhost:3000/api/v1/rules       # → 5 rules seeded
```

---

## 10. SIEM Application Configuration

### 10.1 Activate Correlation Rules

```bash
# List rules
curl -s http://localhost:3000/api/v1/rules | jq

# Activate R001 — R005
for id in R001 R002 R003 R004 R005; do
  curl -s -X PATCH "http://localhost:3000/api/v1/rules/$id" \
    -H "Content-Type: application/json" \
    -d '{"is_active": true}'
done

# Verify all active
curl -s http://localhost:3000/api/v1/rules | jq '.[] | {id, name, is_active}'
```

### 10.2 Verify SOAR

```bash
curl -s http://localhost:3000/api/v1/soar/health | jq
# Expected: provider: "pfsense", configured: true, reachable: true

curl -s http://localhost:3000/api/v1/soar/rules | jq '.count'
```

---

## 11. Log Ingestion Pipeline

### 11.1 Winlogbeat Configuration (DC & Target Win)

On BOTH Windows VMs, install Winlogbeat from elastic.co, then configure:

`C:\Program Files\Winlogbeat\winlogbeat.yml`:

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624,4625,4634,4647,4648,4672,4768,4769,4776,4771,1102,104,103
    include_xml: true

output.elasticsearch:
  hosts: ["192.168.133.1:9200"]        # ← Your Windows host Docker
  index: "winlogbeat-%{+yyyy.MM.dd}"

processors:
  - add_fields:
      target: ''
      fields:
        source_type: "windows_security"
```

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

---

## 12. MITRE ATT&CK — Correlation Rules

| Rule | Name | MITRE Technique | Severity | SOAR |
|------|------|-----------------|----------|------|
| R001 | Brute Force | **T1110** | HIGH+ | ✅ `block_ip` (AUTO) |
| R002 | Pass-the-Hash | **T1550.002** | HIGH | ❌ Manual |
| R003 | Data Exfiltration | **T1041** | CRITICAL | ❌ Manual |
| R004 | Log Clearing | **T1070.001** | CRITICAL | ✅ `isolate_endpoint` (CONFIRM) |
| R005 | Reconnaissance | **T1046** | WARNING+ | ❌ Manual |

---

## 13. Attack Simulations — Step by Step

### 13.1 Brute Force (T1110 → R001 → SOAR block_ip) ⭐ STAR OF THE SHOW

**Goal**: 15-second demo showing the full SOAR pipeline.

**Step 1**: Allow RDP through pfSense temporarily

```
Firewall → Rules → WAN → Add:
  Action: Pass
  Protocol: TCP
  Source: 192.168.243.10/32
  Destination: 192.168.133.20/32
  Port: 3389
  Description: "DEMO RDP"
```

**Step 2**: Launch brute force from Kali

```bash
hydra -l jmiller -P /tmp/demo-passwords.txt rdp://192.168.133.20 -V -t 2
```

Create a small password file for speed:

```bash
echo -e "Wrong1\nWrong2\nWrong3\nWrong4\nPassw0rd!" > /tmp/demo-passwords.txt
```

**Step 3**: Watch detection in SIEM logs

```bash
docker logs siem-backend --tail 30 --follow | grep -E "R001|SOAR|block_ip|INCIDENT"
```

Expected within 60 seconds:

```
[DATA] R001: scanned 8 matching events
[ALERT] R001: 1 incident(s) created!
[NEW] Incident <id>: HIGH - Brute force from 192.168.243.10: 8 failures in 15s
[SOAR] Triggering playbook "block_ip" for incident <id>
[block_ip] Blocked 192.168.243.10: Security incident detected
[block_ip] pfSense rule created: SmartSIEM-Block-192.168.243.10
```

**Step 4**: Verify the block

```bash
# From Kali — connection now fails
nc -zv 192.168.133.20 3389   # → Connection refused / timeout

# Via API
curl http://localhost:3000/api/v1/soar/check-ip/192.168.243.10
# → {"blocked": true, ...}
```

**Step 5**: Unblock for next demo

```bash
curl -X POST http://localhost:3000/api/v1/soar/unblock-ip \
  -H "Content-Type: application/json" -d '{"ip": "192.168.243.10"}'
```

---

### 13.2 All Other Attacks

| # | Attack | Command | Expected Rule |
|---|--------|---------|---------------|
| 2 | Recon (T1046) | `nmap -sS 192.168.133.20 -p 1-10000` | R005 |
| 3 | Pass-the-Hash (T1550) | `net use \\192.168.133.10\C$ /user:admin.bob P@ssw0rd123!` (from Target Win) | R002 |
| 4 | Log Clear (T1070) | `wevtutil cl Security` (from Target Win as admin) | R004 + SOAR `isolate_endpoint` |
| 5 | Exfil (T1041) | Large file upload via PowerShell | R003 |

---

## 14. SOAR Playbook Verification

### 14.1 All Playbook Endpoints

```bash
# Block an IP
curl -X POST http://localhost:3000/api/v1/soar/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.243.10", "reason": "SOC block"}'

# Block a port
curl -X POST http://localhost:3000/api/v1/soar/block-port \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.243.10", "port": 3389, "protocol": "tcp"}'

# Temporary block (10 min)
curl -X POST http://localhost:3000/api/v1/soar/temporary-block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.243.10", "ttl_seconds": 600}'

# Isolate host
curl -X POST http://localhost:3000/api/v1/soar/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.133.20", "reason": "Isolate"}'

# Check IP
curl http://localhost:3000/api/v1/soar/check-ip/192.168.243.10

# List rules
curl http://localhost:3000/api/v1/soar/rules

# Unblock
curl -X POST http://localhost:3000/api/v1/soar/unblock-ip \
  -H "Content-Type: application/json" -d '{"ip": "192.168.243.10"}'

# Delete specific rule
curl -X DELETE "http://localhost:3000/api/v1/soar/rule/SmartSIEM-Block-192.168.243.10"

# Health
curl http://localhost:3000/api/v1/soar/health

# Execute playbook from incident
curl -X POST http://localhost:3000/api/v1/soar/execute \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "<id>", "playbook_name": "block_ip", "mode": "AUTO"}'

# Check execution history
GET /api/v1/incidents/{{id}} → check playbook_executions field
```

### 14.2 AUTO vs CONFIRM Mode

| Mode | Behavior | Used By |
|------|----------|---------|
| **AUTO** | Fires immediately on detection | R001 (brute force) |
| **CONFIRM** | Awaits analyst approval via API | R004 (isolation — hi risk) |

---

## 15. Jury Demo Script (15 min)

### 15.1 Pre-Demo Checklist

```
✅ Docker Desktop running
✅ All 4 VMs running (VMware)
✅ pfSense web UI at http://192.168.133.128
✅ SOAR health: curl http://localhost:3000/api/v1/soar/health
✅ All 5 rules active
✅ Kali can ping 192.168.243.128 (WAN reachable)
✅ Kali CANNOT ping 192.168.133.10 (WAN→LAN blocked)
✅ pfSense WAN allows RDP from Kali to Target (temporary rule added)
✅ Windows Terminal pre-opened with:
   Tab 1: docker logs siem-backend --tail 20 --follow
   Tab 2: Kali SSH session (or Kali terminal)
   Tab 3: curl commands ready
```

### 15.2 Demo Flow

| Time | Action |
|------|--------|
| 0:00 | **Architecture** — Show the 4 VMs in VMware, explain network topology |
| 0:30 | **SOAR Health** — Run `curl /soar/health` → pfSense connected |
| 1:00 | **Rules** — `curl /rules` → all 5 active |
| 1:30 | **Live Logs** — Show `docker logs` tailing with correlation cycles |
| 2:00 | **Attack: Brute Force** — Run Hydra from Kali (pre-scripted) |
| 2:30 | **DETECTION** — Show `[ALERT] R001: 1 incident(s) created!` |
| 2:45 | **SOAR RESPONSE** — Show `[SOAR] block_ip` + `SmartSIEM-Block-192.168.243.10` |
| 3:00 | **VERIFY BLOCK** — `nc -zv 192.168.133.20 3389` → FAILS |
| 3:30 | **Unblock** — `curl /soar/unblock-ip` → clean up for next demo |
| 4:00 | **Attack: Recon** — Nmap scan from Kali → R005 triggers |
| 5:00 | **Attack: Log Clear** — wevtutil on Target Win → R004 + isolate_endpoint |
| 6:00 | **API Tour** — Demo health, rules, check-ip, block-port endpoints |
| 7:00 | **Q&A** — Talk about abstraction, MITRE mapping, AUTO vs CONFIRM |
| 8:00 | **Wrap up** |

### 15.3 Key Talking Points

- *"The attacker is blocked within 60 seconds without human intervention."*
- *"Every SOAR action is fully audited — incident_id, playbook_name, severity."*
- *"We can swap firewall providers (pfSense ↔ Windows Defender) with one env var."*
- *"Critical infrastructure IPs are protected — the SOAR system cannot block itself."*
- *"AUTO mode for fast response, CONFIRM mode for high-impact actions needing SOC approval."*

---

## 16. Troubleshooting

### Correlation rules not firing
```bash
curl http://localhost:3000/api/v1/rules | jq '.[] | {id, is_active}'
curl -s "http://localhost:9200/winlogbeat-*/_search?q=event_id:4625" | jq '.hits.total'
```

### SOAR not blocking
```bash
curl http://localhost:3000/api/v1/soar/health
curl -s -H "X-API-Key: YOUR_KEY" http://192.168.133.128/api/v2/system/info
docker logs siem-backend --tail 50 | grep -i "SOAR\|FAIL\|error"
```

### Logs not reaching ES
```powershell
# Check from Windows host
curl http://localhost:9200/_cat/indices?v

# Check from Windows VMs
Test-NetConnection -ComputerName 192.168.133.1 -Port 9200
```

### VMware networking
```
Kali can't ping pfSense WAN?   → Check NIC 1 is "NAT Network: WAN"
VM can't reach internet?        → Check pfSense NAT is configured
VMs can't reach host?           → Check Windows Firewall rules
```

---

## More

### SSH Lateral Movement Detection (T1021.004)

If you want to run the lab without a Windows VM, R002 can detect SSH-based lateral movement instead of NTLM Pass-the-Hash. The detection is:

1. User **admin** normally logs in from the management console (192.168.133.0/24)
2. Suddenly the same **admin** user authenticates via SSH from **192.168.243.10** (Kali — WAN side)
3. This is anomalous — internal admin accounts don't authenticate from the WAN

This is still **T1021.004 SSH** under MITRE **TA0008 Lateral Movement** — just a different sub-technique than the Pass-the-Hash in the main lab.

### Expanding to More Targets

To simulate more complex lateral movement chains, add a third Linux VM:

```
Target A (192.168.133.20)
     │
     │ SSH from compromised admin account
     ▼
Target B (192.168.133.1281)
     │
     │ R002 detects the unusual east-west SSH
     ▼
SOAR isolate_endpoint (CONFIRM)
```

### Custom Rules

The correlation framework supports adding new rules easily. See `src/correlation/rules/` — implement `DetectionRule` interface, register in `CorrelationService`, seed into the database.

> **Version**: 2.0 (VMware + Docker Desktop)
> **Updated**: 2026-07-07
> **Author**: Smart SIEM CTU Team — UCAC/ICAM