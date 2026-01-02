#!/bin/bash
# Script d'installation de l'agent Wazuh sur une machine distante (honeypot)

WAZUH_MANAGER_IP="192.168.1.100"
AGENT_NAME="honeypot-agent"

echo "[+] Téléchargement de l'agent Wazuh..."
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb

echo "[+] Installation de l'agent..."
sudo WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb

echo "[+] Configuration du service..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "[+] Vérification de l'état..."
sudo systemctl status wazuh-agent

echo "[+] Agent Wazuh installé et connecté au manager: $WAZUH_MANAGER_IP"