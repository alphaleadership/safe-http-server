# Safe HTTP Server

A simple HTTP server with security features like IP blocking, rate limiting, and endpoint blocking.

## Installation

```bash
npm install safe-blocklist-http-server
```

## Usage

```javascript
const SafeHttpServer = require('safe-blocklist-http-server');

// A simple request handler app
const app = (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, World!');
};

// Configuration options
const options = {
  expiryTime: 60000, // 1 minute
  timeLimit: 60000, // 1 minute
  requestLimit: 100,
  blockedEndpoints: ['/blocked']
};

const server = new SafeHttpServer(3000, './blocklist.json', app, options);

server.listen();

console.log('Server listening on port 3000');
```

## Features

### IP Blocking

The server can block IP addresses. The blocklist is stored in a JSON file.

### Rate Limiting

The server limits the number of requests from a single IP address within a given time frame. If the limit is exceeded, the IP address is blocked.

### Request Expiry

The server forgets about requests after a certain amount of time. This is useful to prevent the request map from growing indefinitely.

### Endpoint Blocking

The server can be configured to immediately block requests to specific endpoints.

## API

### `new SafeHttpServer(port, blocklistPath, app, options)`

Creates a new `SafeHttpServer` instance.

*   `port` (Number): The port to listen on.
*   `blocklistPath` (String): The path to the blocklist JSON file.
*   `app` (Function): The request handler function.
*   `options` (Object): Configuration options.
    *   `expiryTime` (Number): The time in milliseconds after which a request is forgotten. Defaults to `60000`.
    *   `timeLimit` (Number): The time in milliseconds for the rate limiting window. Defaults to `60000`.
    *   `requestLimit` (Number): The maximum number of requests allowed from a single IP within the `timeLimit`. Defaults to `100`.
    *   `blockedEndpoints` (Array<String>): An array of endpoint URLs to block immediately. Defaults to `[]`.

### `listen()`

Starts the HTTP server.

### `close()`

Stops the HTTP server and clears the cleanup interval.

### `save()`

Saves the current blocklist to the file.
