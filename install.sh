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
    if (fs.existsSync('config.json')) {
        fs.unlinkSync('config.json');
    }
    fs.writeFileSync('config.json', JSON.stringify(config, null, 4));
}
createConfig();
"

print_status "Oppdaterer systemet..."
apt update
apt upgrade -y

print_status "Installerer nødvendige pakker..."
if [ "$USE_SSL" = true ]; then
    apt install -y nodejs npm nginx certbot python3-certbot-nginx build-essential python3 make g++ net-tools
else
    apt install -y nodejs npm nginx build-essential python3 make g++ net-tools
fi

print_status "Oppretter applikasjonsmappe..."
mkdir -p /opt/multipass-manager
cp -r ./* /opt/multipass-manager/

print_status "Installerer Node.js avhengigheter..."
cd /opt/multipass-manager

# Fjern node_modules hvis den eksisterer
rm -rf node_modules

# Installer node-gyp globalt først
npm install -g node-gyp

# Installer build-essential og python hvis de ikke allerede er installert
apt install -y build-essential python3

# Sett python path
which python3 > /dev/null 2>&1 && {
    print_status "Setter python path..."
    npm config set python $(which python3)
}

# Installer dependencies
npm install --verbose || {
    print_error "npm install feilet"
    echo "npm feillogg:"
    cat npm-debug.log
    exit 1
}

# Spesiell håndtering av node-pty
print_status "Rekompilerer node-pty..."
cd node_modules/node-pty
rm -rf build
npm install --build-from-source || {
    print_error "Kompilering av node-pty feilet"
    exit 1
}

# Kjør node-gyp clean først
node-gyp clean || {
    print_error "node-gyp clean feilet"
    exit 1
}

# Kjør configure og build
node-gyp configure || {
    print_error "node-gyp configure feilet"
    exit 1
}

node-gyp rebuild || {
    print_error "node-gyp rebuild feilet"
    exit 1
}

cd ../..

# Verifiser at pty.node eksisterer og er gyldig
if [ ! -f "node_modules/node-pty/build/Release/pty.node" ]; then
    print_error "pty.node ble ikke bygget"
    exit 1
fi

# Verifiser at server.js eksisterer
if [ ! -f "server.js" ]; then
    print_error "server.js mangler i /opt/multipass-manager/"
    echo "Innhold i /opt/multipass-manager/:"
    ls -la
    exit 1
fi

# Sjekk Node.js versjon
print_status "Node.js versjon:"
node --version
print_status "NPM versjon:"
npm --version

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
Environment=USE_SSL=${USE_SSL}
StandardOutput=journal
StandardError=journal
# Legg til mer detaljert logging
Environment=DEBUG=*

[Install]
WantedBy=multi-user.target
EOL

print_status "Konfigurerer Nginx..."
if [ "$USE_SSL" = true ]; then
    # Først setter vi opp en midlertidig HTTP-konfigurasjon
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
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL
else
    # For ikke-SSL oppsett (lokal testing/utvikling)
    cat > /etc/nginx/sites-available/multipass-manager.conf << EOL
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    
    # Sikkerhetstiltak
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
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL
fi

print_status "Aktiverer Nginx konfigurasjon..."
ln -sf /etc/nginx/sites-available/multipass-manager.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default  # Fjern standard konfigurasjon
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
if ! systemctl start multipass-manager; then
    print_error "Kunne ikke starte multipass-manager"
    echo "Systemd status:"
    systemctl status multipass-manager
    echo "Journalctl output:"
    journalctl -u multipass-manager -n 50 --no-pager
    exit 1
fi

# Vent litt og sjekk om tjenesten fortsatt kjører
sleep 5
if ! systemctl is-active --quiet multipass-manager; then
    print_error "multipass-manager startet men stoppet etter få sekunder"
    echo "Siste loggmeldinger:"
    journalctl -u multipass-manager -n 50 --no-pager
    exit 1
fi

# Legg til feilsøkingsinformasjon
print_status "Sjekker status på tjenester..."
echo "Nginx status:"
systemctl status nginx
echo "Multipass-manager status:"
systemctl status multipass-manager
echo "Sjekker om port 3000 er i bruk:"
netstat -tulpn | grep 3000
echo "Siste linjer fra journalctl for multipass-manager:"
journalctl -u multipass-manager -n 50 --no-pager

# Sjekk at Node.js-applikasjonen kjører
if ! netstat -tulpn | grep :3000 > /dev/null; then
    print_error "Node.js-applikasjonen ser ikke ut til å kjøre på port 3000!"
    print_warning "Sjekk feilmeldinger med: journalctl -u multipass-manager -n 50"
fi

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
