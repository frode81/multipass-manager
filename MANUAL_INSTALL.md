# Manuell Installasjon

Dette dokumentet beskriver den manuelle installasjonsprosessen for Multipass Manager.

## Systemkrav

- Ubuntu Server 20.04 LTS eller nyere
- Node.js 18 eller nyere
- Nginx
- Multipass
- Let's Encrypt (for SSL)

## Steg-for-Steg Installasjon

1. Installer nødvendige pakker:
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y nodejs npm nginx multipass certbot python3-certbot-nginx
```

2. Klon repositoriet:
```bash
sudo mkdir -p /opt/multipass-manager
sudo git clone https://github.com/yourusername/multipass-manager.git /opt/multipass-manager
```

3. Installer avhengigheter:
```bash
cd /opt/multipass-manager
sudo npm install
```

4. Opprett config.json:
```bash
sudo nano /opt/multipass-manager/config.json
```

Legg inn følgende innhold (erstatt verdiene):
```json
{
    "session": {
        "secret": "GENERER_EN_TILFELDIG_STRENG"
    },
    "users": [
        {
            "username": "admin",
            "password": "DITT_PASSORD",
            "role": "admin",
            "firstLogin": false
        }
    ]
}
```

For å generere en sikker session secret:
```bash
openssl rand -base64 32
```

5. Konfigurer systemd service:
```bash
sudo nano /etc/systemd/system/multipass-manager.service
```

Legg inn følgende innhold:
```ini
[Unit]
Description=Multipass Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/multipass-manager
ExecStart=/usr/bin/node server.js
Restart=always
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

6. Start tjenesten:
```bash
sudo systemctl daemon-reload
sudo systemctl enable multipass-manager
sudo systemctl start multipass-manager
```

7. Konfigurer Nginx:
```bash
sudo nano /etc/nginx/sites-available/multipass-manager.conf
```

Legg inn følgende innhold (erstatt domenenavn):
```nginx
server {
    listen 80;
    server_name ditt.domene.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

8. Aktiver Nginx konfigurasjon:
```bash
sudo ln -s /etc/nginx/sites-available/multipass-manager.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

9. Konfigurer brannmur:
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

10. Sett opp SSL:
```bash
sudo certbot --nginx -d ditt.domene.com
```

## Verifisering

1. Sjekk at tjenesten kjører:
```bash
sudo systemctl status multipass-manager
```

2. Sjekk at Nginx er konfigurert riktig:
```bash
sudo nginx -t
```

3. Test tilgang til webgrensesnittet:
```bash
curl -I https://ditt.domene.com
```

## Feilsøking

Se hovedfilen README.md for feilsøkingsinstruksjoner. 