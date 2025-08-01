const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const StaticBlockList = require("static-blocklist");
let blocke = [];
try {
    const urlFilePath = path.join(__dirname, "url.txt");
    if (fs.existsSync(urlFilePath)) {
        blocke = fs.readFileSync(urlFilePath, "utf8").split("\n").filter(Boolean);
    }
} catch (err) {
    console.error("Warning: Could not load url.txt:", err.message);
}

module.exports = class SafeHttpServer {
    constructor(port, blocklistPath, app, { expiryTime = 60000, timeLimit = 60000, requestLimit = 100, blockedEndpoints = [] } = {}) {
        this.expiryTime = expiryTime;
        this.timeLimit = timeLimit;
        this.requestLimit = requestLimit;
        this.blockedEndpoints = [...blockedEndpoints, ...blocke];
        this.requestMap = new Map();
        this.port = port
        this.blocklist = new StaticBlockList(blocklistPath)
        this.app = app
        this.server = http.createServer(this.handleRequest.bind(this))

        // Periodically clean up expired entries from the request map
        this.cleanupInterval = setInterval(this.cleanup.bind(this), this.expiryTime);
    }

    cleanup() {
        const now = Date.now();
        for (const [ip, client] of this.requestMap.entries()) {
            if (now - client.lastRequestTime > this.expiryTime) {
                this.requestMap.delete(ip);
            }
        }
    }

    /**
     * Récupère l'adresse IP du client en tenant compte des en-têtes de proxy
     * @param {http.IncomingMessage} req - La requête HTTP
     * @returns {string} L'adresse IP nettoyée ou 'unknown' si non trouvée
     */
    getClientIP(req) {
        // Vérifier les en-têtes de proxy courants
        const forwarded = req.headers['x-forwarded-for'];
        let ip = null;

        if (forwarded) {
            // Prendre la première adresse si plusieurs sont présentes (cas des chaînes de proxy)
            ip = typeof forwarded === 'string' 
                ? forwarded.split(',')[0].trim() 
                : forwarded[0].split(',')[0].trim();
        } else if (req.headers['x-real-ip']) {
            ip = req.headers['x-real-ip'];
        } else if (req.socket && req.socket.remoteAddress) {
            ip = req.socket.remoteAddress;
        }

        // Nettoyer l'adresse IP (enlever le préfixe ::ffff: pour les adresses IPv4)
        if (ip) {
            ip = ip.replace(/^::ffff:/, '');
            // Valider le format de l'adresse IP
            if (net.isIP(ip)) {
                return ip;
            }
        }
        
        return 'unknown';
    }

    handleRequest(req, res) {
        const clientIP = this.getClientIP(req);

        if (this.blockedEndpoints.some(endpoint => req.url.includes(endpoint))) {
            console.log(clientIP)
            this.blocklist.addAddress(clientIP, req.socket.family);
            this.save();
            res.writeHead(403, { "Content-Type": "text/plain" });
            res.end("Forbidden");
            return;
        }

        if (this.blocklist.check(clientIP, req.socket.family)) {
            res.writeHead(403, { "Content-Type": "text/plain" })
            res.end("Forbidden")
            return
        }

        const currentTime = Date.now();
        const client = this.requestMap.get(clientIP);

        if (client) {
            let timeDiff = currentTime - client.lastRequestTime;

            if (timeDiff < this.timeLimit) {
                let newRequestCount = client.requestCount + 1;

                if (newRequestCount > this.requestLimit) {
                    this.blocklist.addAddress(clientIP, req.socket.family);
                    this.save();
                    res.writeHead(429, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ error: 'request limit exceeded!' }));
                    return;
                }

                this.requestMap.set(clientIP, {
                    requestCount: newRequestCount,
                    lastRequestTime: client.lastRequestTime,
                });
            } else {
                this.requestMap.set(clientIP, {
                    requestCount: 1,
                    lastRequestTime: currentTime,
                });
            }
        } else {
            this.requestMap.set(clientIP, { requestCount: 1, lastRequestTime: currentTime });
        }
        return this.app(req, res)
    }

    listen() {
        this.server.listen(this.port)
    }

    close() {
        this.server.close();
        clearInterval(this.cleanupInterval);
    }

    save() {
        this.blocklist.save()
    }
}

