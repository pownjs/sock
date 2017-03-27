exports.yargs = {
    command: 'sock [options] <iface|file>',
    describe: 'network to websockets pipe',

    builder: function (builder) {
        const banner = require('./banner')

        builder.usage(`${banner}${this.original}`)

        builder.option('filter', {
            type: 'string',
            alias: 'f',
            describe: 'PCAP filter to use'
        })

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

        builder.option('open', {
            type: 'string',
            alias: 'o',
            choices: ['httpview'],
            describe: 'Open inside application'
        })

        builder.example('https://github.com/pownjs/pown-sock', 'tricks, tips and examples')
    },

    handler: (argv) => {
        const banner = require('./banner')

        console.log(banner)

        const chalk = require('chalk')

        // Get instance of the global sock singleton.

        const sock = require('./index')

        // Listen on events.

        sock.on('listening', (server) => {
            console.log(chalk.green('*'), `listening on ${server._server.address().address}:${server._server.address().port}`)

            if (argv.open) {
                const opn = require('opn')

                switch (argv.open) {
                    case 'httpview':
                        opn(`https://httpview.secapps.com/#feedURI=${encodeURIComponent(`ws://${server._server.address().address}:${server._server.address().port}`)}`)

                        break;

                    default:
                        console.error(chalk.red('-'), `unrecognized application ${argv.open}`)
                }
            }
        })

        sock.on('connection', (client) => {
            console.log(chalk.green('*'), `connected from ${client._socket.remoteAddress}:${client._socket.remotePort}`)
        })

        sock.on('error', (error) => {
            console.error(chalk.red('-'), chalk.white.bgRed(error.message || error))
        })

        // Start the server.

        sock.start((argv.iface || argv.file), {filter: argv.filter, host: argv.host, port: argv.port, monitor: argv.monitor, promisc: argv.promisc, write: argv.write}, (err) => {
            if (err) {
                console.error(chalk.red('-'), chalk.white.bgRed(err.message || err))

                process.exit(2)
            }
        })
    }
}
