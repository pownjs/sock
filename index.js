exports.yargs = {
    command: 'sock [options] <iface|file> [filter]',
    describe: 'network to websockets pipe',

    builder: function (builder) {
        const banner = require('./banner')

        builder.usage(`${banner}${this.original}`)

        builder.option('host', {
            type: 'string',
            alias: 'h',
            default: '127.0.0.1',
            describe: 'Bind to host'
        })

        builder.option('port', {
            type: 'number',
            alias: 'p',
            default: 8080,
            describe: 'Bind to port'
        })

        builder.option('monitor', {
            type: 'boolean',
            alias: 'm',
            default: false,
            describe: 'Use monitor mode'
        })

        builder.option('promisc', {
            type: 'boolean',
            alias: 's',
            default: false,
            describe: 'Use promisc mode'
        })

        builder.option('write', {
            type: 'string',
            alias: 'w',
            describe: 'Write to pcap file'
        })
    },

    handler: (argv) => {
        const fs = require('fs')
        const ws = require('ws')
        const chalk = require('chalk')
        const pcap = require('ws-pcap2')
        const banner = require('./banner')

        console.log(banner)

        let messageQueueSize
        let messageQueue

        let session

        const options = {
            filter: argv.filter || '',
            isMonitor: argv.monitor,
            isPromisc: argv.promisc
        }

        if ((_ => { try { return !fs.statSync(argv.file).isDirectory() } catch (e) { return false } })()) {
            try {
                session = new pcap.OfflineSession(argv.iface, options)

                console.log(chalk.white.bgYellow(`[*] reading traffic from ${argv.iface}`))

                messageQueueSize = Infinity
                messageQueue = []
            } catch (e) {
                console.error(chalk.black.bgRed(e.message || e))

                process.exit(1)
            }
        } else {
            if (argv.write) {
                options.outfile = argv.write
            }

            try {
                session = new pcap.Session(argv.iface, options)

                console.log(chalk.black.bgYellow(`[*] intercepting traffic on ${argv.iface}`))

                messageQueueSize = 0
                messageQueue = []
            } catch (e) {
                console.error(chalk.white.bgRed(e.message || e))

                process.exit(1)
            }
        }

        const server = new ws.Server({host: argv.host, port: argv.port})

        server.on('connection', (client) => {
            console.log(`[*] connected from ${client._socket.remoteAddress}:${client._socket.remotePort}`)

            messageQueue.forEach((message) => {
                client.send(message)
            })
        })

        process.on('uncaughtException', (exception) => {
            console.error(chalk.white.bgRed(exception.message || exception))

            server.close()
        })

        process.on('SIGTERM', () => {
            server.close()
        })

        const binding = process.binding('http_parser')
        const HTTPParser = binding.HTTPParser
        const methods = binding.methods

        const kOnHeadersComplete = HTTPParser.kOnHeadersComplete | 0
        const kOnBody = HTTPParser.kOnBody | 0
        const kOnMessageComplete = HTTPParser.kOnMessageComplete | 0

        const trck = new pcap.TCPTracker()

        session.on('packet', (rawPacket) => {
            try {
                let packet = pcap.decode.packet(rawPacket)

                trck.track_packet(packet)
            } catch(e) {
                console.error(chalk.white.bgRed(e.message || e))
            }
        })

        trck.on('session', (session) => {
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

                    if (messageQueue.length < messageQueueSize) {
                        messageQueue.push(packetBuf)
                    }

                    server.clients.forEach((client) => {
                        if (client.readyState === ws.OPEN) {
                            console.log(`sending data to ${client._socket.remoteAddress}:${client._socket.remotePort}`)

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

        const uri = `ws://${argv.host}:${argv.port}`

        console.log(chalk.black.bgYellow(`[*] socket serving on ${uri}`))
    } 
}
