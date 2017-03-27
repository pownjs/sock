const fs = require('fs')
const ws = require('ws')
const pcap = require('ws-pcap2')
const EventEmitter = require('events')

// TODO: server support should be provied by a general-purpose pown module

class Sock extends EventEmitter {
    constructor(options) {
        super()

        this.options(options)

        this.started = false
    }

    options(options) {
        options = options || {}

        this.filter = options.filter || this.filter || ''
        this.host = options.host || this.host || '0.0.0.0'
        this.port = options.port || this.port || 8080
        this.monitor = options.monitor || this.monitor || false
        this.promisc = options.promisc || this.promisc || true
        this.write = options.write || this.write || null
    }

    onConnectionHandler(client) {
        this.messageQueue.forEach((message) => {
            client.send(message)
        })
    }

    start(ifaceORfile, options, done) {
        if (typeof(options) === 'function') {
            done = options
            options = {}
        }

        if (!done) {
            done = (err) => {
                if (err) {
                    throw err
                }
            }
        }

        if (this.started) {
            done(new Error('already started'))

            return
        }

        this.options(options)

        this.started = true

        const conf = {
            filter: this.filter,
            isMonitor: this.monitor,
            isPromisc: this.promisc
        }

        if ((_ => { try { return !fs.statSync(argv.file).isDirectory() } catch (e) { return false } })()) {
            try {
                this.session = new pcap.OfflineSession(ifaceORfile, conf)

                this.messageQueueSize = Infinity
                this.messageQueue = []
            } catch (e) {
                done(e)

                return
            }
        } else {
            if (this.write) {
                conf.outfile = this.write
            }

            try {
                this.session = new pcap.Session(ifaceORfile, conf)

                this.messageQueueSize = 0
                this.messageQueue = []
            } catch (e) {
                done(e)

                return
            }
        }

        const server = new ws.Server({host: this.host, port: this.port})

        server.on('listening', this.emit.bind(this, 'listening', server))
        server.on('connection', this.emit.bind(this, 'connection'))
        server.on('error', this.emit.bind(this, 'error'))
        server.on('headers', this.emit.bind(this, 'headers'))

        server.on('connection', this.onConnectionHandler.bind(this))

        this.server = server

        const httpParser = process.binding('http_parser')
        const HTTPParser = httpParser.HTTPParser
        const methods = httpParser.methods

        const kOnHeadersComplete = HTTPParser.kOnHeadersComplete | 0
        const kOnBody = HTTPParser.kOnBody | 0
        const kOnMessageComplete = HTTPParser.kOnMessageComplete | 0

        const tracker = new pcap.TCPTracker()

        this.session.on('packet', (rawPacket) => {
            try {
                let packet = pcap.decode.packet(rawPacket)

                tracker.track_packet(packet)
            } catch(e) {
                this.emit(e)
            }
        })

        tracker.on('session', (session) => {
            session.req = new HTTPParser(HTTPParser.REQUEST)
            session.res = new HTTPParser(HTTPParser.RESPONSE)

            session.req[kOnHeadersComplete] = (versionMajor, versionMinor, headers, method, url, statusCode, statusMessage, upgrade, shouldKeepAlive) => {
                if (methods[method] === 'CONNECT') {
                    // NOTE: CONNECT may indicate encrypted traffic

                    session.req[kOnHeadersComplete] = null
                    session.req[kOnBody] = null
                    session.req[kOnMessageComplete] = null
                    session.res[kOnHeadersComplete] = null
                    session.res[kOnBody] = null
                    session.res[kOnMessageComplete] = null

                    return
                }

                let head = `${methods[method]} ${url} HTTP/${versionMinor}.${versionMinor}\r\n`

                for (let i = 0; i < headers.length; i += 2) {
                    head += `${headers[i]}: ${headers[i + 1]}\r\n`
                }

                head += '\r\n'

                session.req.buf = new Buffer(head)
            }

            session.req[kOnBody] = (b, start, len) => {
                session.req.buf = Buffer.concat([session.req.buf, b.slice(start, start + len)])
            }
    
            session.req[kOnMessageComplete] = () => {
            }

            session.res[kOnHeadersComplete] = (versionMajor, versionMinor, headers, method, url, statusCode, statusMessage, upgrade, shouldKeepAlive) => {
                let head = `HTTP/${versionMinor}.${versionMinor} ${statusCode} ${statusMessage}\r\n`

                for (let i = 0; i < headers.length; i += 2) {
                    head += `${headers[i]}: ${headers[i + 1]}\r\n`
                }

                head += '\r\n'

                session.res.buf = new Buffer(head)
            }

            session.res[kOnBody] = (b, start, len) => {
                session.res.buf = Buffer.concat([session.res.buf, b.slice(start, start + len)])
            }

            session.res[kOnMessageComplete] = () => {
                if (session.req.buf && session.res.buf) {
                    const headerBuf = Buffer.alloc(4 + 4)

                    // v1: Raw Frames
                    // v2: Raw Sessions (Re-constructed TCP/UDP)
                    // v3: HTTP

                    headerBuf.writeUInt32BE(3, 0)
                    headerBuf.writeUInt32BE(session.req.buf.byteLength, 4)

                    const packetBuf = Buffer.concat([headerBuf, session.req.buf, session.res.buf])

                    if (this.messageQueue.length < this.messageQueueSize) {
                        this.messageQueue.push(packetBuf)
                    }

                    this.server.clients.forEach((client) => {
                        if (client.readyState === ws.OPEN) {
                            client.send(packetBuf)
                        }
                    })
                }
            }

            session.on('data send', (session, data) => {
                session.req.execute(data)
            })

            session.on('data recv', (session, data) => {
                session.res.execute(data)
            })

            session.on('end', (session) => {
                delete session.req
                delete session.res
            })
        })

        this.tracker = tracker
    }

    stop(done) {
        if (!done) {
            done = (err) => {
                if (err) {
                    throw err
                }
            }
        }

        if (!this.started) {
            done(new Error('not started'))

            return
        }

        this.server.close((err) => {
            if (err) {
                done(err)

                return
            }

            try {
                this.session.close()
            } catch (e) {
                console.error(e)

                // too late to go back
            }

            this.started = false

            done(null)
        })
    }
}

module.exports = Sock
