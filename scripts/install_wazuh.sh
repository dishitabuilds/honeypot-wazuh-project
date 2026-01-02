#!/bin/bash
# Script d'installation de Wazuh en mode All-in-One
# Basé sur la documentation officielle Wazuh 4.7.5

echo "[+] Installation de Wazuh Manager, Indexer et Dashboard..."

# Télécharger le script d'installation
curl -so wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Vérifier l'état des services
echo "[+] Vérification des services Wazuh..."
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

echo "[+] Installation terminée."
echo "[+] Accès dashboard: https://<IP>:443"
echo "[+] Identifiants par défaut: admin / (voir le mot de passe généré)"