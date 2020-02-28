const raw = require("raw-socket");
const dns = require("dns").promises;

const icmpSocket = raw.createSocket({ protocol: raw.Protocol.ICMP });

const MAX_HOPS = 64;
const MAX_TIMEOUT_IN_MILLISECONDS = 1000;
const DESTINATION_HOST = process.argv[process.argv.length - 1];
const NO_REVERSE_LOOKUP = process.argv[process.argv.length - 2] === "-n";

let DESTINATION_IP;

let ttl = 1;
let tries = 0;

let startTime;
let timeout;
let previousIP;

startTrace();

async function startTrace() {
  DESTINATION_IP = (await dns.lookup(DESTINATION_HOST)).address;
  console.log(
    `traceroute to ${DESTINATION_HOST} (${DESTINATION_IP}), ${MAX_HOPS} hops max, 42 byte packets`
  );
  sendPacket();
}

function sendPacket() {
  if (tries >= 3) {
    tries = 0;
    ttl++;
  }
  tries++;

  var header = Buffer.alloc(12);
  header.writeUInt8(0x8, 0); //type (echo request)
  header.writeUInt8(0x0, 1); //if type = 8 - doesn't matter
  icmpSocket.setOption(
    raw.SocketLevel.IPPROTO_IP,
    raw.SocketOption.IP_TTL,
    ttl
  );

  header.writeUInt16BE(
    raw.createChecksum({ buffer: header, length: 2, offset: 0 }),
    2
  );

  startTime = process.hrtime();
  icmpSocket.send(header, 0, 12, DESTINATION_IP, function(err) {
    if (err) throw err;
    timeout = setTimeout(handleReply, MAX_TIMEOUT_IN_MILLISECONDS);
  });
}

function handleReply(ip, symbolicAddress) {
  if (timeout) {
    clearTimeout(timeout);
  }
  if (ip) {
    const elapsedTime = `${(process.hrtime(startTime)[1] / 1000000).toFixed(
      3
    )} ms`;

    if (ip === previousIP) {
      process.stdout.write(`  ${elapsedTime}`);
    } else if (tries === 1) {
      process.stdout.write(
        `\n ${ttl} ${
          symbolicAddress ? symbolicAddress : ip
        } (${ip}) ${elapsedTime}`
      );
    } else {
      process.stdout.write(
        `\n  ${symbolicAddress ? symbolicAddress : ip} (${ip}) ${elapsedTime}`
      );
    }
  } else {
    if (tries === 1) {
      process.stdout.write(`\n ${ttl}  * `);
    } else {
      process.stdout.write(`* `);
    }
  }

  if ((ip == DESTINATION_IP && tries === 3) || ttl >= MAX_HOPS) {
    console.log("");
    process.exit();
  }

  previousIP = ip;

  setTimeout(() => sendPacket(), 0);
}

setTimeout(
  () =>
    icmpSocket.on("message", async function(buffer, ip) {
      try {
        let symbolicAddress;
        if (!NO_REVERSE_LOOKUP) {
          symbolicAddress = await dns.reverse(ip);
        }
        handleReply(ip, symbolicAddress[0]);
      } catch (e) {
        handleReply(ip);
      }
    }),
  0
);
