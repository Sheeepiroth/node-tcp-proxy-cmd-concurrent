var net = require("net");
var tls = require('tls');
var fs = require('fs');
var util = require('util');
var child_process = require("child_process");

module.exports.createProxy = function(proxyPort,
    serviceHost, servicePort, options) {
    return new TcpProxy(proxyPort, serviceHost, servicePort, options);
};

function uniqueKey(socket) {
    var key = socket.remoteAddress + ":" + socket.remotePort;
    return key;
}

function parse(o) {
    if (typeof o === "string") {
        return o.split(",");
    } else if (typeof o === "number") {
        return parse(o.toString());
    } else if (Array.isArray(o)) {
        return o;
    } else {
        throw new Error("cannot parse object: " + o);
    }
}

function TcpProxy(proxyPort, serviceHost, servicePort, options) {
    this.proxyPort = proxyPort;
    this.serviceHosts = parse(serviceHost);
    this.servicePorts = parse(servicePort);
    this.serviceHostIndex = -1;
    this.options = this.parseOptions(options);
    this.proxyTlsOptions = {
        passphrase: this.options.passphrase,
        secureProtocol: "TLSv1_2_method"
    };
    if (this.options.tls) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        this.proxyTlsOptions.pfx = fs.readFileSync(this.options.pfx);
    }
    this.serviceTlsOptions = {
        rejectUnauthorized: this.options.rejectUnauthorized,
        secureProtocol: "TLSv1_2_method"
    };
    this.proxySockets = {};
    this.programProcess = null;
    this.programSocket = null;

    if (this.options.identUsers.length !== 0) {
        this.users = this.options.identUsers;
        this.log('Will only allow these users: '.concat(this.users.join(', ')));
    } else {
        this.log('Will allow all users');
    }
    if (this.options.allowedIPs.length !== 0) {
        this.allowedIPs = this.options.allowedIPs;
    }

    if (this.options.enableProgramProxy) {
        if (!this.options.programToExecute || !this.options.programRemoteHost || !this.options.programRemotePort) {
            this.log("Program proxy enabled but missing required configuration: programToExecute, programRemoteHost, or programRemotePort. Disabling.");
            this.options.enableProgramProxy = false;
        } else {
            this.log(`Program proxy enabled: ${this.options.programToExecute} -> ${this.options.programRemoteHost}:${this.options.programRemotePort}`);
        }
    }
    this.createListener();
}

TcpProxy.prototype.parseOptions = function(options) {
    return Object.assign({
        quiet: true,
        pfx: require.resolve('./cert.pfx'),
        passphrase: 'abcd',
        rejectUnauthorized: true,
        identUsers: [],
        allowedIPs: [],
        // New options for program proxy
        enableProgramProxy: false,
        programToExecute: null,
        programArgs: [],
        programRemoteHost: null,
        programRemotePort: null,
        programTls: false,
        programRejectUnauthorized: true
    }, options);
};

TcpProxy.prototype.createListener = function() {
    var self = this;
    if (self.options.tls) {
        self.server = tls.createServer(self.options.customTlsOptions || self.proxyTlsOptions, function(socket) {
            self.handleClientConnection(socket);
        });
    } else {
        self.server = net.createServer(function(socket) {
            self.handleClientConnection(socket);
        });
    }
    self.server.listen(self.proxyPort, self.options.hostname, function() {
        self.log(`TCP proxy listening on port ${self.proxyPort}, forwarding to ${self.serviceHosts.join(',')}:${self.servicePorts.join(',')}`);
        if (self.options.enableProgramProxy) {
            self.startProgramProxy();
        }
    });
};

TcpProxy.prototype.handleClientConnection = function(socket) {
    var self = this;
    if (self.users) {
        self.handleAuth(socket);
    } else {
        self.handleClient(socket);
    }
};

// RFC 1413 authentication
TcpProxy.prototype.handleAuth = function(proxySocket) {
    var self = this;
    if (self.allowedIPs.includes(proxySocket.remoteAddress)) {
        self.handleClient(proxySocket);
        return;
    }
    var query = util.format("%d, %d", proxySocket.remotePort, this.proxyPort);
    var ident = new net.Socket();
    var resp = undefined;
    ident.on('error', function(e) {
        resp = false;
        ident.destroy();
    });
    ident.on('data', function(data) {
        resp = data.toString().trim();
        ident.destroy();
    });
    ident.on('close', function(data) {
        if (!resp) {
            self.log('No identd');
            proxySocket.destroy();
            return;
        }
        var user = resp.split(':').pop();
        if (!self.users.includes(user)) {
            self.log(util.format('User "%s" unauthorized', user));
            proxySocket.destroy();
        } else {
            self.handleClient(proxySocket);
        }
    });
    ident.connect(113, proxySocket.remoteAddress, function() {
        ident.write(query);
        ident.end();
    });
};

TcpProxy.prototype.handleClient = function(proxySocket) {
    var self = this;
    var key = uniqueKey(proxySocket);
    self.proxySockets[`${key}`] = proxySocket;
    var context = {
        buffers: [],
        connected: false,
        proxySocket: proxySocket
    };
    proxySocket.on("data", function(data) {
        self.handleUpstreamData(context, data);
    });
    proxySocket.on("close", function(hadError) {
        delete self.proxySockets[uniqueKey(proxySocket)];
        if (context.serviceSocket !== undefined) {
            context.serviceSocket.destroy();
        }
    });
    proxySocket.on("error", function(e) {
        if (context.serviceSocket !== undefined) {
            context.serviceSocket.destroy();
        }
    });
};

TcpProxy.prototype.handleUpstreamData = function(context, data) {
    var self = this;
    Promise.resolve(self.intercept(self.options.upstream, context, data))
        .then((processedData) => {
            if (context.connected) {
                context.serviceSocket.write(processedData);
            } else {
                context.buffers[context.buffers.length] = processedData;
                if (context.serviceSocket === undefined) {
                    self.createServiceSocket(context);
                }
            }
        });
};

TcpProxy.prototype.createServiceSocket = function(context) {
    var self = this;
    var options = self.parseServiceOptions(context);
    if (self.options.tls === "both") {
        context.serviceSocket = tls.connect(options, function() {
            self.writeBuffer(context);
        });
    } else {
        context.serviceSocket = new net.Socket();
        context.serviceSocket.connect(options, function() {
            self.writeBuffer(context);
        });
    }
    context.serviceSocket.on("data", function(data) {
        Promise.resolve(self.intercept(self.options.downstream, context, data))
            .then((processedData) => context.proxySocket.write(processedData));
    });
    context.serviceSocket.on("close", function(hadError) {
        if (context.proxySocket !== undefined) {
            context.proxySocket.destroy();
        }
    });
    context.serviceSocket.on("error", function(e) {
        if (context.proxySocket !== undefined) {
            context.proxySocket.destroy();
        }
    });
};

TcpProxy.prototype.parseServiceOptions = function(context) {
    var self = this;
    var i = self.getServiceHostIndex(context.proxySocket);
    return Object.assign({
        port: self.servicePorts[parseInt(i, 10)],
        host: self.serviceHosts[parseInt(i, 10)],
        localAddress: self.options.localAddress,
        localPort: self.options.localPort
    }, self.serviceTlsOptions);
};

TcpProxy.prototype.getServiceHostIndex = function(proxySocket) {
    this.serviceHostIndex++;
    if (this.serviceHostIndex == this.serviceHosts.length) {
        this.serviceHostIndex = 0;
    }
    var index = this.serviceHostIndex;
    if (this.options.serviceHostSelected) {
        index = this.options.serviceHostSelected(proxySocket, index);
    }
    return index;
};

TcpProxy.prototype.writeBuffer = function(context) {
    context.connected = true;
    if (context.buffers.length > 0) {
        for (var i = 0; i < context.buffers.length; i++) {
            context.serviceSocket.write(context.buffers[parseInt(i, 10)]);
        }
    }
};

TcpProxy.prototype.end = function() {
    this.log('Shutting down proxy...');
    this.server.close();
    for (var key in this.proxySockets) {
        this.proxySockets[`${key}`].destroy();
    }
    this.server.unref();
    this.killProgramProxy();
};

TcpProxy.prototype.log = function(msg) {
    if (!this.options.quiet) {
        console.log(msg);
    }
};

TcpProxy.prototype.intercept = function(interceptor, context, data) {
    if (interceptor) {
        return interceptor(context, data);
    }
    return data;
};

TcpProxy.prototype.startProgramProxy = function() {
    var self = this;
    if (!self.options.enableProgramProxy || self.programProcess || self.programSocket) {
        // Already started, not enabled, or misconfigured (checked in constructor)
        return;
    }

    self.log(`Starting program: ${self.options.programToExecute} ${self.options.programArgs.join(' ')}`);
    try {
        self.programProcess = child_process.spawn(
            self.options.programToExecute,
            self.options.programArgs,
            { stdio: ['pipe', 'pipe', 'pipe'] } // Ensure stdio streams are available
        );
    } catch (e) {
        self.log(`Error spawning program: ${e.message}`);
        self.programProcess = null;
        return;
    }

    self.programProcess.on('error', function(err) {
        self.log(`Program process error: ${err.message}`);
        self.killProgramProxy();
    });

    self.programProcess.on('exit', function(code, signal) {
        self.log(`Program process exited with code ${code}${signal ? `, signal ${signal}` : ''}`);
        self.killProgramProxy();
    });

    var programSocketOptions = {
        host: self.options.programRemoteHost,
        port: self.options.programRemotePort,
    };

    if (self.options.programTls) {
        Object.assign(programSocketOptions, {
            rejectUnauthorized: self.options.programRejectUnauthorized,
        });
        self.log(`Connecting program socket to ${programSocketOptions.host}:${programSocketOptions.port} using TLS`);
        self.programSocket = tls.connect(programSocketOptions);
    } else {
        self.log(`Connecting program socket to ${programSocketOptions.host}:${programSocketOptions.port} using TCP`);
        self.programSocket = new net.Socket();
        self.programSocket.connect(programSocketOptions.port, programSocketOptions.host);
    }

    self.programSocket.on('connect', function() {
        self.log(`Program socket connected to ${self.options.programRemoteHost}:${self.options.programRemotePort}`);
        if (!self.programProcess || !self.programSocket) { // Check if already cleaned up
            self.log('Program process or socket became null before piping could be set up.');
            self.killProgramProxy();
            return;
        }
        self.programProcess.stdout.pipe(self.programSocket, { end: false });
        self.programProcess.stderr.pipe(self.programSocket, { end: false });
        self.programSocket.pipe(self.programProcess.stdin);

        self.programSocket.on('end', () => {
            self.log('Program socket received FIN from remote.');
            if (self.programProcess && self.programProcess.stdin && !self.programProcess.stdin.destroyed) {
                self.programProcess.stdin.end();
            }
        });
    });

    self.programSocket.on('error', function(err) {
        self.log(`Program socket error: ${err.message}`);
        self.killProgramProxy();
    });

    self.programSocket.on('close', function(hadError) {
        self.log(`Program socket closed.${hadError ? ' Due to error.' : ''}`);
        self.killProgramProxy();
    });
};

TcpProxy.prototype.killProgramProxy = function() {
    var self = this;
    if (self.programProcess) {
        const proc = self.programProcess;
        self.programProcess = null;
        self.log('Killing program process.');
        if (proc.stdout) proc.stdout.unpipe();
        if (proc.stderr) proc.stderr.unpipe();
        // Note: proc.stdin is a Writable, socket is Readable. socket.unpipe(proc.stdin)
        proc.kill('SIGTERM');
    }
    if (self.programSocket) {
        const sock = self.programSocket;
        self.programSocket = null;
        self.log('Destroying program socket.');
        sock.destroy();
    }
};
