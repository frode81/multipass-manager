const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const os = require('os');
const pty = require('node-pty');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const port = 3000;
const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

// Generer en tilfeldig session secret hvis den ikke finnes
if (!config.session.secret || config.session.secret === 'ditt-hemmelige-session-token') {
    config.session.secret = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync('config.json', JSON.stringify(config, null, 4));
}

// Grunnleggende middleware
app.use(express.json());
app.use(cookieParser());

// Session håndtering
app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Funksjon for å hente tilgjengelige nettverksgrensesnitt
async function getNetworkInterfaces() {
    const interfaces = os.networkInterfaces();
    const validInterfaces = [];
    
    for (const [name, details] of Object.entries(interfaces)) {
        // Filtrer ut loopback og interne grensesnitt
        if (!name.includes('lo') && !name.includes('docker') && !name.includes('veth')) {
            // Finn IPv4-grensesnitt som er aktive
            const ipv4Interface = details.find(detail => 
                detail.family === 'IPv4' && !detail.internal
            );
            
            if (ipv4Interface) {
                validInterfaces.push(name);
            }
        }
    }
    
    return validInterfaces;
}

// Autentiseringsfunksjoner
function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login.html');
    }

    try {
        const user = jwt.verify(token, config.session.secret);
        req.user = user;

        // Sjekk om brukeren må endre passord
        const userConfig = config.users.find(u => u.username === user.username);
        if (userConfig && userConfig.firstLogin && 
            !req.path.includes('/change-password') && 
            !req.path.includes('/api/change-password')) {
            return res.redirect('/change-password.html');
        }

        next();
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/login.html');
    }
}

// Serve statiske filer som ikke krever autentisering
app.use('/login.html', express.static(path.join(__dirname, 'public/login.html')));
app.use('/change-password.html', express.static(path.join(__dirname, 'public/change-password.html')));
app.use('/favicon.ico', express.static(path.join(__dirname, 'public/favicon.ico')));

// Login endepunkt (krever ikke autentisering)
app.post('/api/login', async (req, res) => {
    console.log('Login forsøk:', { username: req.body.username });
    
    const { username, password } = req.body;
    
    if (!username || !password) {
        console.log('Manglende brukernavn eller passord');
        return res.status(400).json({ error: 'Brukernavn og passord er påkrevd' });
    }

    const user = config.users.find(u => u.username === username);
    console.log('Bruker funnet:', !!user);

    if (!user) {
        return res.status(401).json({ error: 'Ugyldig brukernavn eller passord' });
    }

    // Hvis passordet fortsatt er i klartekst, hash det
    if (!user.password.startsWith('$2b$')) {
        user.password = await bcrypt.hash(user.password, 12);
        fs.writeFileSync('config.json', JSON.stringify(config, null, 4));
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ error: 'Ugyldig brukernavn eller passord' });
    }

    const token = jwt.sign(
        { 
            username: user.username, 
            role: user.role,
            firstLogin: user.firstLogin 
        },
        config.session.secret,
        { expiresIn: '24h' }
    );

    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    });

    console.log('Login vellykket, token satt');
    res.json({ 
        success: true,
        firstLogin: user.firstLogin 
    });
});

// Endepunkt for å endre passord
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = config.users.find(u => u.username === req.user.username);

    if (!user) {
        return res.status(404).json({ error: 'Bruker ikke funnet' });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ error: 'Feil nåværende passord' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.firstLogin = false;
    fs.writeFileSync('config.json', JSON.stringify(config, null, 4));

    res.json({ success: true });
});

// Logout endepunkt
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

// Endepunkt for å hente nettverksgrensesnitt
app.get('/network-interfaces', authenticateToken, async (req, res) => {
    try {
        const interfaces = os.networkInterfaces();
        const validInterfaces = [];
        
        for (const [name, details] of Object.entries(interfaces)) {
            if (!name.includes('lo') && !name.includes('docker') && !name.includes('veth')) {
                const ipv4Interface = details.find(detail => 
                    detail.family === 'IPv4' && !detail.internal
                );
                
                if (ipv4Interface) {
                    validInterfaces.push(name);
                }
            }
        }
        
        res.json(validInterfaces);
    } catch (error) {
        console.error('Feil ved henting av nettverksgrensesnitt:', error);
        res.status(500).json({ 
            error: 'Kunne ikke hente nettverksgrensesnitt',
            details: error.message 
        });
    }
});

// Beskyttede ruter og statiske filer
app.use('/run-command', authenticateToken);
app.use('/', authenticateToken, express.static(path.join(__dirname, 'public')));

// WebSocket autentisering
wss.on('connection', (ws, req) => {
    const token = req.headers.cookie?.split(';')
        .find(c => c.trim().startsWith('token='))
        ?.split('=')[1];

    if (!token) {
        ws.close(1008, 'Ikke autentisert');
        return;
    }

    try {
        jwt.verify(token, config.session.secret);
    } catch (err) {
        ws.close(1008, 'Ugyldig token');
        return;
    }

    // Resten av WebSocket-logikken...
    let ptyProcess = null;
    let retryCount = 0;
    const MAX_RETRIES = 3;

    async function tryConnect(instance) {
        try {
            // Sjekk først at instansen kjører og er tilgjengelig
            const info = await executeCommand(`multipass info ${instance}`);
            if (!info.output.includes('Running')) {
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    data: 'Instance er ikke i kjørende tilstand. Start den først.\r\n' 
                }));
                return false;
            }

            // Vent litt for å la nettverket initialiseres
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Start pty prosess med multipass shell kommando
            ptyProcess = pty.spawn('multipass', ['shell', instance], {
                name: 'xterm-color',
                cols: 80,
                rows: 30,
                cwd: process.env.HOME,
                env: process.env
            });

            // Håndter output fra pty
            ptyProcess.onData(data => {
                ws.send(JSON.stringify({ type: 'output', data: data }));
            });

            // Send ready signal når prosessen er klar
            setTimeout(() => {
                if (ptyProcess) {
                    ws.send(JSON.stringify({ type: 'ready' }));
                }
            }, 1000);

            return true;
        } catch (error) {
            ws.send(JSON.stringify({ type: 'error', data: error.message + '\r\n' }));
            return false;
        }
    }

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'start' && data.instance) {
                retryCount = 0;
                if (ptyProcess) {
                    ptyProcess.kill();
                    ptyProcess = null;
                }
                ws.send(JSON.stringify({ type: 'output', data: 'Kobler til container...\r\n' }));
                await tryConnect(data.instance);
            } else if (data.type === 'input' && ptyProcess) {
                try {
                    ptyProcess.write(data.data);
                } catch (error) {
                    console.error('Feil ved sending av input:', error);
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        data: 'Feil ved sending av input: ' + error.message + '\r\n' 
                    }));
                }
            } else if (data.type === 'resize' && ptyProcess) {
                try {
                    ptyProcess.resize(data.cols, data.rows);
                } catch (error) {
                    console.error('Feil ved endring av terminalstørrelse:', error);
                }
            }
        } catch (error) {
            console.error('Feil ved håndtering av WebSocket-melding:', error);
            ws.send(JSON.stringify({ 
                type: 'error', 
                data: 'Intern feil: ' + error.message + '\r\n' 
            }));
        }
    });

    ws.on('close', () => {
        if (ptyProcess) {
            ptyProcess.kill();
            ptyProcess = null;
        }
    });
});

// Kjør en kommando med timeout og feilhåndtering
function executeCommand(command, timeout = 300000) {
    return new Promise((resolve, reject) => {
        console.log(`Kjører kommando: ${command}`);
        
        const process = exec(command, { timeout }, (error, stdout, stderr) => {
            if (error && error.killed) {
                console.error('Kommando timeout');
                reject(new Error('Kommandoen tok for lang tid'));
                return;
            }

            // Noen multipass-kommandoer sender informasjon til stderr selv om de lykkes
            const output = stdout + (stderr ? '\n' + stderr : '');
            
            if (error) {
                console.error('Kommandofeil:', error);
                console.error('stderr:', stderr);
                reject(new Error(stderr || error.message));
                return;
            }

            console.log('Kommando fullført:', output);
            resolve({ status: 'success', output: output.trim() });
        });

        process.on('error', (error) => {
            console.error('Prosesfeil:', error);
            reject(error);
        });
    });
}

// Middleware for å validere multipass-kommandoer
function validateMultipassCommand(req, res, next) {
    const { command } = req.body;
    
    if (!command || typeof command !== 'string') {
        return res.status(400).json({ error: 'Ugyldig kommando' });
    }
    
    // Tillat mktemp-kommando for å opprette midlertidige filer
    if (command.startsWith('mktemp -p /tmp')) {
        next();
        return;
    }
    
    // Tillat cloud-init relaterte kommandoer
    if (command.startsWith('echo ') && command.includes('cloud-config')) {
        next();
        return;
    }
    
    // Tillat rm-kommando for midlertidige filer
    if (command.startsWith('rm ') && (
        command.includes('cloud-init-') || 
        command.startsWith('rm /tmp/')
    )) {
        next();
        return;
    }
    
    if (!command.startsWith('multipass ')) {
        return res.status(400).json({ error: 'Kun multipass-kommandoer er tillatt' });
    }
    
    // Liste over tillatte kommandoer
    const allowedCommands = [
        'launch', 'list', 'info', 'start', 'stop', 'delete', 'purge', 
        'shell', 'transfer', 'exec', 'mount', 'snapshot', 'restore'  // Lagt til snapshot og restore
    ];
    const commandPart = command.split(' ')[1];
    
    if (!allowedCommands.includes(commandPart)) {
        return res.status(400).json({ error: 'Ugyldig multipass-kommando' });
    }
    
    next();
}

// Funksjon for å håndtere SSH-nøkkel operasjoner
async function handleSSHKeyOperation(command) {
    console.log('Håndterer SSH-nøkkel operasjon:', command);
    
    try {
        // Hvis det er en echo-kommando, skriv til temp-fil
        if (command.startsWith('echo')) {
            const tempDir = path.join(os.tmpdir(), 'multipass-manager');
            console.log('Bruker temp-mappe:', tempDir);
            
            // Opprett temp-mappe hvis den ikke eksisterer
            if (!fs.existsSync(tempDir)) {
                console.log('Oppretter temp-mappe');
                fs.mkdirSync(tempDir, { recursive: true });
            }
            
            // Finn filnavnet (siste del av kommandoen etter >)
            const fileNameMatch = command.match(/>\s*(\S+)$/);
            if (!fileNameMatch) {
                throw new Error('Kunne ikke finne filnavn i kommandoen');
            }
            const fileName = fileNameMatch[1];
            
            // Hent ut innholdet (alt mellom første ' og siste ')
            const contentMatch = command.match(/echo\s+'([^']+)'/);
            if (!contentMatch) {
                throw new Error('Kunne ikke finne innhold i kommandoen');
            }
            const content = contentMatch[1];
            
            const tempPath = path.join(tempDir, path.basename(fileName));
            console.log('Skriver til temp-fil:', tempPath);
            
            // Skriv innhold til temp-fil
            fs.writeFileSync(tempPath, content + '\n', { mode: 0o600 });
            return { status: 'success', output: `Skrev til ${tempPath}` };
        }
        
        // Hvis det er en rm-kommando, slett temp-fil
        if (command.startsWith('rm')) {
            const fileName = command.split(' ')[1];
            const tempDir = path.join(os.tmpdir(), 'multipass-manager');
            const tempPath = path.join(tempDir, path.basename(fileName));
            console.log('Sletter temp-fil:', tempPath);
            
            if (fs.existsSync(tempPath)) {
                fs.unlinkSync(tempPath);
                console.log('Temp-fil slettet');
            } else {
                console.log('Temp-fil eksisterer ikke:', tempPath);
            }
            return { status: 'success', output: `Slettet ${tempPath}` };
        }
        
        // For multipass-kommandoer, bruk executeCommand
        console.log('Kjører multipass-kommando:', command);
        return executeCommand(command);
    } catch (error) {
        console.error('Feil i handleSSHKeyOperation:', error);
        throw error;
    }
}

// Oppdater run-command endepunktet
app.post('/run-command', validateMultipassCommand, async (req, res) => {
    const { command } = req.body;
    console.log('Mottok kommando:', command);
    
    try {
        let result;
        
        // Håndter SSH-nøkkel relaterte kommandoer
        if (command.startsWith('echo') || command.startsWith('rm') || 
            command.includes('transfer') || command.includes('exec')) {
            console.log('Håndterer som SSH-nøkkel operasjon');
            result = await handleSSHKeyOperation(command);
        } else {
            // Sett lengre timeout for launch-kommandoer
            const timeout = command.includes('launch') ? 1200000 : 30000;
            
            // Legg til forsinkelse for visse kommandoer
            if (command.includes('delete') || command.includes('stop')) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            
            result = await executeCommand(command, timeout);
        }
        
        console.log('Kommando fullført med resultat:', result);
        res.json(result);
    } catch (error) {
        console.error('Detaljert feil ved kjøring av kommando:', {
            command,
            error: error.message,
            stack: error.stack
        });
        
        res.status(500).json({ 
            error: error.message,
            details: error.toString(),
            stack: error.stack
        });
    }
});

// Helsesjekk endepunkt
app.get('/health', async (req, res) => {
    try {
        const [version, list] = await Promise.all([
            executeCommand('multipass version'),
            executeCommand('multipass list')
        ]);
        
        res.json({
            status: 'ok',
            version: version.trim(),
            instances: list.trim().split('\n').length - 1
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            error: 'Multipass er ikke tilgjengelig',
            details: error.message
        });
    }
});

// Endre server.listen til å bruke https i produksjon
if (process.env.NODE_ENV === 'production') {
    const https = require('https');
    const fs = require('fs');
    const privateKey = fs.readFileSync('privkey.pem', 'utf8');
    const certificate = fs.readFileSync('cert.pem', 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    
    const httpsServer = https.createServer(credentials, app);
    httpsServer.listen(443, () => {
        console.log('HTTPS server kjører på port 443');
    });
} else {
    server.listen(port, async () => {
        console.log(`Server kjører på http://localhost:${port}`);
        try {
            const version = await executeCommand('multipass version');
            console.log('Multipass versjon:', version);
            
            const list = await executeCommand('multipass list');
            console.log('Aktive instances:\n', list);
        } catch (error) {
            console.error('ADVARSEL: Multipass er ikke tilgjengelig');
            console.error('Feilmelding:', error.message);
        }
    });
} 