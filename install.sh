#!/bin/bash

# Farger for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Funksjon for å vise fremgang
print_status() {
    echo -e "${GREEN}>>> ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}>>> ${1}${NC}"
}

print_error() {
    echo -e "${RED}>>> ${1}${NC}"
}

# Sjekk om skriptet kjøres som root
if [ "$EUID" -ne 0 ]; then 
    print_error "Dette skriptet må kjøres som root (sudo)"
    exit 1
fi

# Sjekk om Multipass er installert
print_status "Sjekker Multipass installasjon..."
if ! command -v multipass &> /dev/null; then
    print_warning "Multipass er ikke installert. Installerer..."
    
    # Sjekk om snap er installert
    if ! command -v snap &> /dev/null; then
        print_status "Installerer snap..."
        apt install -y snapd
        snap wait system seed.loaded
    fi
    
    # Installer Multipass
    snap install multipass
    
    # Verifiser installasjonen
    if ! command -v multipass &> /dev/null; then
        print_error "Kunne ikke installere Multipass. Vennligst installer manuelt og prøv igjen."
        exit 1
    fi
    
    print_status "Multipass er nå installert!"
else
    print_status "Multipass er allerede installert."
fi

# Test Multipass
print_status "Tester Multipass..."
if ! multipass version &> /dev/null; then
    print_error "Multipass er installert men ser ut til å ikke fungere korrekt."
    print_error "Vennligst kjør 'multipass version' manuelt for å se feilen."
    exit 1
fi

# Spør om installasjonstype
print_status "Velg installasjonstype:"
echo "1) Med domenenavn (anbefalt for produksjon, inkluderer SSL)"
echo "2) Med IP-adresse (for lokal testing/utvikling)"
read -p "Velg (1/2): " INSTALL_TYPE

if [ "$INSTALL_TYPE" = "1" ]; then
    # Spør etter domenenavn
    read -p "Skriv inn ditt domenenavn (f.eks. multipass.example.com): " DOMAIN_NAME
    USE_SSL=true
else
    # Hent IP-adresse automatisk eller la bruker spesifisere
    echo "Tilgjengelige IP-adresser på denne maskinen:"
    ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1
    read -p "Skriv inn IP-adressen du vil bruke (trykk Enter for å bruke første tilgjengelige): " DOMAIN_NAME
    
    if [ -z "$DOMAIN_NAME" ]; then
        DOMAIN_NAME=$(ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1 | head -n1)
        if [ -z "$DOMAIN_NAME" ]; then
            print_error "Kunne ikke finne en gyldig IP-adresse"
            exit 1
        fi
    fi
    USE_SSL=false
    print_status "Bruker IP-adresse: ${DOMAIN_NAME}"
fi

# Spør etter brukernavn og passord for admin-bruker
read -p "Velg brukernavn for admin: " ADMIN_USER
read -s -p "Velg passord for admin: " ADMIN_PASS
echo

# Generer en sikker session secret
SESSION_SECRET=$(openssl rand -hex 32)

# Opprett config.json med bcrypt-hashet passord
node -e "
const bcrypt = require('bcrypt');
const fs = require('fs');

async function createConfig() {
    const hashedPassword = await bcrypt.hash('${ADMIN_PASS}', 12);
    const config = {
        users: [{
            username: '${ADMIN_USER}',
            password: hashedPassword,
            role: 'admin',
            firstLogin: true
        }],
        session: {
            secret: '${SESSION_SECRET}',
            expiresIn: '24h'
        }
    };
    fs.writeFileSync('config.json', JSON.stringify(config, null, 4));
}
createConfig();
"

print_status "Oppdaterer systemet..."
apt update
apt upgrade -y

print_status "Installerer nødvendige pakker..."
if [ "$USE_SSL" = true ]; then
    apt install -y nodejs npm nginx certbot python3-certbot-nginx
else
    apt install -y nodejs npm nginx
fi

print_status "Oppretter applikasjonsmappe..."
mkdir -p /opt/multipass-manager
cp -r ./* /opt/multipass-manager/

print_status "Installerer Node.js avhengigheter..."
cd /opt/multipass-manager
npm install

print_status "Konfigurerer systemd service..."
cat > /etc/systemd/system/multipass-manager.service << EOL
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
EOL

print_status "Konfigurerer Nginx..."
if [ "$USE_SSL" = true ]; then
    cat > /etc/nginx/sites-available/multipass-manager.conf << EOL
server {
    listen 80;
    server_name ${DOMAIN_NAME};

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOL
else
    cat > /etc/nginx/sites-available/multipass-manager.conf << EOL
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    
    # Sikkerhetstiltak for IP-basert tilgang
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOL
fi

print_status "Aktiverer Nginx konfigurasjon..."
ln -sf /etc/nginx/sites-available/multipass-manager.conf /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx

print_status "Konfigurerer brannmur..."
ufw allow 80/tcp
if [ "$USE_SSL" = true ]; then
    ufw allow 443/tcp
fi
ufw --force enable

print_status "Starter tjenesten..."
systemctl daemon-reload
systemctl enable multipass-manager
systemctl start multipass-manager

# Modifiser SSL-delen
if [ "$USE_SSL" = true ]; then
    print_status "Setter opp SSL..."
    certbot --nginx -d ${DOMAIN_NAME} --non-interactive --agree-tos --email admin@${DOMAIN_NAME} --redirect
    
    print_status "Installasjon fullført!"
    echo "Du kan nå besøke https://${DOMAIN_NAME}"
else
    print_status "Installasjon fullført!"
    echo "Du kan nå besøke http://${DOMAIN_NAME}"
fi

echo "Logg inn med:"
echo "Brukernavn: ${ADMIN_USER}"
echo "Passord: [ditt valgte passord]"

print_warning "VIKTIG: Ta backup av følgende filer:"
echo "- /opt/multipass-manager/config.json"
echo "- /etc/nginx/sites-available/multipass-manager.conf"
if [ "$USE_SSL" = true ]; then
    echo "- /etc/letsencrypt/"
fi 