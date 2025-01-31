#!/bin/bash

# Fargekoder for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Loggfunksjon med tidsstempel
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${1}"
}

info() {
    log "${GREEN}INFO: ${1}${NC}"
}

warn() {
    log "${YELLOW}ADVARSEL: ${1}${NC}"
}

error() {
    log "${RED}FEIL: ${1}${NC}"
}

# Funksjon for å sjekke om en kommando eksisterer
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Funksjon for å sjekke systemkrav
check_requirements() {
    info "Sjekker systemkrav..."
    
    # Sjekk om vi kjører som root
    if [ "$EUID" -ne 0 ]; then 
        error "Dette skriptet må kjøres som root (sudo)"
        exit 1
    fi

    # Sjekk operativsystem
    if [ ! -f /etc/os-release ]; then
        error "Kunne ikke identifisere operativsystemet"
        exit 1
    fi

    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            info "Kjører på støttet operativsystem: $PRETTY_NAME"
            ;;
        *)
            error "Dette skriptet støtter kun Ubuntu og Debian"
            exit 1
            ;;
    esac

    # Sjekk minimum systemressurser
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 2048 ]; then
        warn "Systemet har mindre enn 2GB RAM. Dette kan påvirke ytelsen."
    fi

    # Sjekk diskplass
    FREE_SPACE=$(df -m /opt | awk 'NR==2 {print $4}')
    if [ "$FREE_SPACE" -lt 5120 ]; then
        error "Mindre enn 5GB ledig diskplass. Minimum 5GB kreves."
        exit 1
    fi
}

# Funksjon for å installere nødvendige pakker
install_dependencies() {
    info "Oppdaterer pakkelister..."
    apt-get update || {
        error "Kunne ikke oppdatere pakkelister"
        exit 1
    }

    info "Installerer nødvendige pakker..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        nodejs \
        npm \
        nginx \
        python3 \
        make \
        g++ \
        pkg-config \
        build-essential \
        net-tools \
        ufw || {
        error "Kunne ikke installere nødvendige pakker"
        exit 1
    }
}

# Funksjon for å installere Multipass
install_multipass() {
    info "Installerer Multipass..."
    
    if ! command_exists snap; then
        info "Installerer snap..."
        apt-get install -y snapd
        snap wait system seed.loaded
    fi
    
    snap install multipass || {
        error "Kunne ikke installere Multipass"
        exit 1
    }

    # Verifiser Multipass-installasjonen
    if ! multipass version; then
        error "Multipass er installert men fungerer ikke korrekt"
        exit 1
    fi
}

# Funksjon for å sette opp applikasjonen
setup_application() {
    info "Setter opp applikasjonen..."
    
    # Opprett applikasjonsmappe
    mkdir -p /opt/multipass-manager
    cp -r ./* /opt/multipass-manager/ || {
        error "Kunne ikke kopiere applikasjonsfiler"
        exit 1
    }

    cd /opt/multipass-manager || {
        error "Kunne ikke navigere til applikasjonsmappen"
        exit 1
    }

    # Installer Node.js-avhengigheter
    npm ci --production || {
        error "Kunne ikke installere Node.js-avhengigheter"
        exit 1
    }

    # Spesialhåndtering av node-pty
    info "Bygger node-pty..."
    npm rebuild node-pty --update-binary || {
        error "Kunne ikke bygge node-pty"
        exit 1
    }
}

# Funksjon for å sette opp systemd-tjeneste
setup_systemd() {
    info "Konfigurerer systemd-tjeneste..."
    
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
StandardOutput=journal
StandardError=journal
Environment=DEBUG=*

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl enable multipass-manager
    systemctl start multipass-manager || {
        error "Kunne ikke starte multipass-manager tjenesten"
        journalctl -u multipass-manager -n 50 --no-pager
        exit 1
    }
}

# Funksjon for å sette opp Nginx
setup_nginx() {
    info "Konfigurerer Nginx..."
    
    cat > /etc/nginx/sites-available/multipass-manager.conf << EOL
server {
    listen 80;
    server_name localhost;

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

    ln -sf /etc/nginx/sites-available/multipass-manager.conf /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t || {
        error "Nginx konfigurasjon er ugyldig"
        exit 1
    }
    
    systemctl restart nginx || {
        error "Kunne ikke starte Nginx"
        exit 1
    }
}

# Funksjon for å sette opp brannmur
setup_firewall() {
    info "Konfigurerer brannmur..."
    
    ufw allow 80/tcp
    ufw allow 22/tcp  # SSH
    ufw --force enable
}

# Hovedfunksjon
main() {
    info "Starter installasjon av Multipass Manager..."
    
    check_requirements
    install_dependencies
    install_multipass
    setup_application
    setup_systemd
    setup_nginx
    setup_firewall
    
    info "Installasjon fullført!"
    info "Du kan nå besøke http://localhost eller server IP-adressen"
    info "Sjekk /opt/multipass-manager/config.json for påloggingsinformasjon"
}

# Start installasjonen
main "$@" 
