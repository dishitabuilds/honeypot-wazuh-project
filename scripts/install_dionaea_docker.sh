#!/bin/bash
# Script d'installation de Dionaea Honeypot via Docker

echo "[+] Installation de Docker et Docker Compose..."
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker

echo "[+] Téléchargement de l'image Dionaea..."
sudo docker pull dinotools/dionaea:latest

echo "[+] Création du dossier de logs..."
sudo mkdir -p /opt/dionaea/log

echo "[+] Lancement du conteneur Dionaea..."
sudo docker run -d \
  --name dionaea \
  --network host \
  -v /opt/dionaea/log:/opt/dionaea/var/log \
  dinotools/dionaea

echo "[+] Vérification du conteneur..."
sudo docker ps | grep dionaea

echo "[+] Installation terminée."
echo "[+] Dionaea est en cours d'exécution (ports variés: SMB, FTP, HTTP, etc.)"
echo "[+] Logs: /opt/dionaea/log/dionaea/"
echo "[+] Pour voir les logs en temps réel: tail -f /opt/dionaea/log/dionaea/dionaea.log"