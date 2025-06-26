const http = require("node:http")
const fs = require("node:fs")
const path = require("node:path")
const StaticBlockList = require("./static-blocklist")

module.exports = class SafeHttpServer {
    constructor(port, blocklistPath,app,expiryTime=60000,timeLimit=60000,requestLimit=100) {
        this.expiryTime = expiryTime;
        this.timeLimit = timeLimit;
        this.requestLimit = requestLimit;
        this.currentTime = Date.now();
        this.requestMap = new Map();
        this.port = port
        this.blocklist = new StaticBlockList(blocklistPath)
        this.app = app
        this.server = http.createServer(this.handleRequest.bind(this))
    }
    handleRequest(req, res) {
        if (this.blocklist.check(req.socket.remoteAddress,req.socket.family)) {
            res.writeHead(403, { "Content-Type": "text/plain" })
            res.end("Forbidden")
            return
        }
        const clientIP = req.ip;
        const client = this.requestMap.get(clientIP);
        
  if (client) {
    // difference between  clients last request time and current time
    let timeDiff = this.currentTime - client.lastRequestTime;

    if (timeDiff < this.timeLimit) {
      //
      let newRequestCount = client.requestCount + 1;

      /* 
      if request count is more than the limit then further requests are denied
      until clean up function resets the request count for the client
      */
      if (newRequestCount > this.requestLimit) {
        this.blocklist.add(req.socket.remoteAddress,req.socket.family)
        this.save()
        res.status(429).json({ error: 'request limit exceeded!' });
        return;
      }

      /*
      if request count is within limit 
      then request map is updated with the new request count
      */
      this.requestMap.set(clientIP, {
        requestCount: newRequestCount,
        lastRequestTime: client.lastRequestTime,
      });
    } else {
      // reset request count if time difference is greater than the limit
      this.requestMap.set(clientIP, {
        requestCount: 1,
        lastRequestTime: currentTime,
      });
    }
  } else {
    // create a new entry if client is not present in request map
    this.requestMap.set(clientIP, { requestCount: 1, lastRequestTime: currentTime });
  }
        this.app(req, res)
    }
    listen() {
        this.server.listen(this.port)
    }
    save() {
        this.blocklist.save()
    }
}
