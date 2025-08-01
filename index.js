const http = require("node:http")
const fs = require("node:fs")
const path = require("node:path")
const StaticBlockList = require("static-blocklist")
const blocke=fs.readFileSync(path.join(__dirname, "url.txt"), "utf8").split("\n")
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

    handleRequest(req, res) {
        const clientIP = req.socket.remoteAddress;

        if (this.blockedEndpoints.some(endpoint => req.url.includes(endpoint))) {
            this.blocklist.add(clientIP, req.socket.family);
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
                    this.blocklist.add(clientIP, req.socket.family)
                    this.save()
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

