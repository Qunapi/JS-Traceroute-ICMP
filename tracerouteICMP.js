const raw = require("raw-socket");
const dns = require("dns").promises;

const icmpSocket = raw.createSocket({ protocol: raw.Protocol.ICMP });

const MAX_HOPS = 30;
const MAX_TIMEOUT_IN_MILLISECONDS = 1000;

const DESTINATION_HOST = process.argv[process.argv.length - 1];
const NO_REVERSE_LOOKUP = process.argv[process.argv.length - 2] === "-n";
let DESTINATION_IP;

let ttl = 1;
let tries = 0;
let timeout;

let startTime;
let previousIP;

startTrace();

async function startTrace() {
  DESTINATION_IP = (await dns.lookup(DESTINATION_HOST)).address;
  console.log(
    `traceroute to ${DESTINATION_HOST} (${DESTINATION_IP}), ${MAX_HOPS} hops max, 42 byte packets`
  );
  sendPacket();
}

const MAX_TRIES = 3;

function sendPacket() {
  if (tries >= MAX_TRIES) {
    tries = 0;
    ttl++;
  }
  tries++;

  const ECHO_REQUEST = 8;
  const OFFSET = 0;
  const ICMP_PACKET_SIZE = 12;

  var icmpPacket = Buffer.alloc(ICMP_PACKET_SIZE);

  icmpPacket.writeUInt8(ECHO_REQUEST, OFFSET);
  icmpSocket.setOption(
    raw.SocketLevel.IPPROTO_IP,
    raw.SocketOption.IP_TTL,
    ttl
  );
  const PACKET_SIZE = 8;
  const CHECKSUM_OFFSET = 2;

  icmpPacket.writeUInt16BE(
    raw.createChecksum({
      buffer: icmpPacket,
      length: PACKET_SIZE,
      offset: OFFSET
    }),
    CHECKSUM_OFFSET
  );

  startTime = process.hrtime();
  icmpSocket.send(
    icmpPacket,
    OFFSET,
    ICMP_PACKET_SIZE,
    DESTINATION_IP,
    function(err) {
      if (err) throw err;
      timeout = setTimeout(handleReply, MAX_TIMEOUT_IN_MILLISECONDS);
    }
  );
}

function handleReply(ip, symbolicAddress) {
  if (timeout) {
    clearTimeout(timeout);
  }

  const NANOSECONDS = 1;
  const MS_MODIFIER = 1000000;
  if (ip) {
    const elapsedTime = `${(
      process.hrtime(startTime)[NANOSECONDS] / MS_MODIFIER
    ).toFixed(3)} ms`;

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
    console.log("\n");
    process.exit();
  }

  previousIP = ip;

  sendPacket();
}

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
});
