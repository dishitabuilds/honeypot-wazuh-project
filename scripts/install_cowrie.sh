#!/bin/bash
# Script d'installation de Cowrie Honeypot (SSH/Telnet)
# Ne pas exécuter en root

echo "[+] Installation des dépendances..."
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip libssl-dev libffi-dev build-essential

echo "[+] Création de l'utilisateur cowrie..."
sudo useradd -m -s /bin/bash cowrie
echo "[!] Veuillez définir un mot de passe pour l'utilisateur cowrie :"
sudo passwd cowrie
sudo usermod -aG sudo cowrie

echo "[+] Passage à l'utilisateur cowrie..."
sudo -u cowrie bash << 'EOF'
cd /home/cowrie
echo "[+] Téléchargement de Cowrie..."
git clone https://github.com/cowrie/cowrie.git
cd cowrie

echo "[+] Création de l'environnement virtuel..."
python3 -m venv cowrie-env
source cowrie-env/bin/activate

echo "[+] Installation des packages Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Configuration de Cowrie..."
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Configuration basique pour écouter sur les ports 2222 et 2223
sed -i "s/listen_endpoints = tcp:2222:interface=0.0.0.0/#listen_endpoints = tcp:2222:interface=0.0.0.0/" etc/cowrie.cfg
sed -i "s/listen_endpoints = tcp:2223:interface=0.0.0.0/#listen_endpoints = tcp:2223:interface=0.0.0.0/" etc/cowrie.cfg

echo "[ssh]" >> etc/cowrie.cfg
echo "enabled = true" >> etc/cowrie.cfg
echo "listen_endpoints = tcp:2222:interface=0.0.0.0" >> etc/cowrie.cfg
echo "" >> etc/cowrie.cfg
echo "[telnet]" >> etc/cowrie.cfg
echo "enabled = true" >> etc/cowrie.cfg
echo "listen_endpoints = tcp:2223:interface=0.0.0.0" >> etc/cowrie.cfg

echo "[+] Installation du package Cowrie..."
pip install -e .

echo "[+] Démarrage de Cowrie..."
./bin/cowrie start

echo "[+] Vérification de l'état..."
./bin/cowrie status
EOF

echo "[+] Installation Cowrie terminée."
echo "[+] Cowrie écoute sur:"
echo "    SSH: port 2222"
echo "    Telnet: port 2223"
echo "[+] Logs: /home/cowrie/cowrie/var/log/cowrie/"