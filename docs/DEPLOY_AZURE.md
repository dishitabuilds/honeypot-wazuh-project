# Deploying the honeypot to Azure for real attack data

This guide puts the honeypot on a public Azure VM so it captures **genuine
internet attack traffic** instead of the simulator. Expect real SSH brute-force
attempts within the first hour and a steady stream of scans within a day.

You are using **Azure for Students** (unlocked by your `@sot.pdpu.ac.in` email),
which gives **$100 free credit, no credit card required**. A B2s VM running this
stack costs roughly $30/month, so the credit covers 2–3 months — plenty to
collect a good dataset. **Delete the resource group when you're done** to stop
spending credit.

---

## ⚠️ Read this first — safety rules

1. **This must run on a throwaway Azure VM, never from your home network or
   laptop.** The VM is disposable; delete it when the project ends.
2. **Cowrie and Dionaea are safe to expose** — they are fake, contained services.
   Attackers' "commands" never actually execute. The thing you must protect is the
   **VM host itself**, which is what the steps below harden.
3. **Move your own admin SSH off port 22 before deploying**, because Cowrie takes
   over port 22. Do the steps *in order* or you can lock yourself out.
4. **Lock the dashboard (8080) and your admin SSH (2200) to your own IP** in the
   Network Security Group. Everything else is open to the world on purpose.

---

## Step 1 — Create an SSH key on your Windows machine

In PowerShell (skip if you already have `~/.ssh/id_ed25519.pub`):

```powershell
ssh-keygen -t ed25519 -C "honeypot-azure"
# press Enter to accept the default path; set a passphrase or leave empty
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub   # copy this — you'll paste it into Azure
```

---

## Step 2 — Create the VM in the Azure Portal

Portal → **Create a resource → Virtual machine**, then:

| Field | Value |
|-------|-------|
| Resource group | Create new: `honeypot-rg` (easy to delete everything later) |
| VM name | `honeypot-vm` |
| Region | Central India (or nearest) |
| Image | **Ubuntu Server 24.04 LTS** |
| Size | **Standard_B2s** (2 vCPU, 4 GB) — B1ms (2 GB) is the budget minimum |
| Authentication type | **SSH public key** |
| Username | `azureadmin` |
| SSH public key source | **Use existing public key** → paste the key from Step 1 |
| Public inbound ports | **Allow selected → SSH (22)** *(temporary — we move it in Step 4)* |

Create it, then copy the VM's **Public IP address** from the overview page.
Below, replace `<VM_IP>` with it everywhere.

---

## Step 3 — Install Docker on the VM

SSH in (still on port 22 for now):

```bash
ssh azureadmin@<VM_IP>
```

Then install Docker + Compose:

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
```

Log out and back in (`exit`, then `ssh` again) so the docker group applies.

---

## Step 4 — Move admin SSH to port 2200 (do this BEFORE deploying)

Cowrie needs port 22, so your real SSH has to move. Do it carefully to avoid a
lockout — we keep 22 open until 2200 is proven working.

**4a. First add the NSG rule for 2200** (Portal → `honeypot-vm` → Networking →
Network settings → **Create port rule → Inbound**):

| Setting | Value |
|---------|-------|
| Source | **My IP address** (recommended) or Any |
| Destination port ranges | `2200` |
| Protocol | TCP |
| Action | Allow |
| Priority | `300` |
| Name | `admin-ssh-2200` |

**4b. Then tell sshd to listen on both ports**, on the VM:

```bash
echo -e "Port 22\nPort 2200" | sudo tee /etc/ssh/sshd_config.d/honeypot.conf
sudo systemctl restart ssh
```

**4c. In a NEW PowerShell window, prove 2200 works** *(don't close your current
session until this succeeds)*:

```powershell
ssh -p 2200 azureadmin@<VM_IP>
```

**4d. Once 2200 works, drop port 22 from your sshd** so Cowrie can use it:

```bash
echo "Port 2200" | sudo tee /etc/ssh/sshd_config.d/honeypot.conf
sudo systemctl restart ssh
```

From now on you always connect with `ssh -p 2200 azureadmin@<VM_IP>`.

---

## Step 5 — Open the honeypot ports in the NSG

Add these **inbound** rules (same Networking screen as 4a). The honeypot ports are
open to the world on purpose; the two admin ports are locked to your IP.

| Name | Port | Source | Priority |
|------|------|--------|----------|
| cowrie-ssh | 22 | Any | 310 |
| cowrie-telnet | 23 | Any | 320 |
| dionaea-ftp | 21 | Any | 330 |
| dionaea-smb | 445 | Any | 340 |
| dionaea-mssql | 1433 | Any | 350 |
| dionaea-mysql | 3306 | Any | 360 |
| webtrap-http | 80 | Any | 370 |
| dashboard-8080 | 8080 | **My IP address** | 380 |

You can now **delete the default `SSH` rule** that allowed 22 to your IP from VM
creation — port 22 belongs to Cowrie now, and your admin access is on 2200.

---

## Step 6 — Deploy the stack

On the VM:

```bash
git clone <your-repo-url> honeypot && cd honeypot
cp .env.example .env
nano .env
```

In `.env`, set at least these (the dashboard is now internet-reachable, so it
needs a login):

```
DASH_USER=admin
DASH_PASS=<a-strong-password>
RETENTION_DAYS=14
# optional but recommended — free key from abuseipdb.com adds IP reputation:
ABUSEIPDB_KEY=<your-key>
```

Then launch with the **production** compose file:

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker ps                        # all four containers should be Up
curl -s localhost:8080/api/health
```

---

## Step 7 — Watch real attacks roll in

Open `http://<VM_IP>:8080` in your browser (works because you allowed 8080 from
your IP) and log in with the `DASH_USER`/`DASH_PASS` you set. Within an hour or so
you'll see real source IPs, real countries, and real brute-force credential
attempts — **no simulator needed**. Leave it running 3–4 weeks to build the
dataset for your results chapter.

Quick sanity check from the VM itself:

```bash
docker logs -f hp-cowrie          # watch live SSH login attempts hit the sensor
```

---

## Step 8 — When you're done: stop the spend

- **Pause (keep data):** Portal → VM → **Stop (deallocate)**. Compute billing
  stops; you keep the disk and can restart later.
- **Delete everything:** Portal → Resource groups → `honeypot-rg` → **Delete
  resource group**. This removes the VM, disk, IP and NSG in one go so no credit
  keeps draining.

**Before deleting, pull your collected data off the VM** so you keep it for the
report:

```powershell
scp -P 2200 azureadmin@<VM_IP>:~/honeypot/data/honeypot.db ./honeypot-realdata.db
```

You can then point the local dashboard at that DB to present the real numbers
offline.

---

## Cost & housekeeping notes

- **B2s ≈ $30/mo** running 24/7; **Stop (deallocate)** whenever you're not
  actively collecting to stretch the $100 credit.
- Honeypots occasionally trip cloud-provider **abuse detection**. Azure is
  generally fine with academic honeypots, but if you get an abuse notice, reply
  explaining it's a contained honeypot research project — don't ignore it.
- Set a **budget alert**: Portal → Cost Management → Budgets → alert at $50 so a
  forgotten VM can't silently eat the whole credit.
