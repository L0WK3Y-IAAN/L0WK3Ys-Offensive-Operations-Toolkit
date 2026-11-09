'use strict';

function decodeSockaddr(address) {
 if (address.isNull()) return 'null';

 try {
  const family = address.add(1).readU8();
  const port = (address.add(2).readU8() << 8) | address.add(3).readU8();

  if (family === 2) { // AF_INET
   const octets = [];
   for (let i = 0; i < 4; i++) octets.push(address.add(4 + i).readU8());
   return octets.join('.') + ':' + port;
  }

  if (family === 30) { // AF_INET6 on Darwin
   const bytes = new Uint8Array(address.add(8).readByteArray(16));
   const groups = [];
   for (let i = 0; i < bytes.length; i += 2) {
    groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
   }
   return '[' + groups.join(':') + ']:' + port;
  }

  return 'family=' + family;
 } catch (error) {
  return 'decode-error: ' + error;
 }
}

function attachIfPresent(name, callbacks) {
 const address = Module.findGlobalExportByName(name);
 if (address === null) {
  console.log('[-] Export unavailable: ' + name);
  return;
 }
 Interceptor.attach(address, callbacks);
 console.log('[+] Tracing ' + name + ' at ' + address);
}

attachIfPresent('getaddrinfo', {
 onEnter(args) {
  if (!args[0].isNull()) {
   console.log('[DNS] ' + args[0].readUtf8String());
  }
 }
});

attachIfPresent('connect', {
 onEnter(args) {
  this.fd = args[0].toInt32();
  this.destination = decodeSockaddr(args[1]);
  console.log('[CONNECT] fd=' + this.fd + ' -> ' + this.destination);
 },
 onLeave(result) {
  console.log('[CONNECT-RESULT] fd=' + this.fd + ' -> ' + this.destination +
   ' result=' + result.toInt32());
 }
});

attachIfPresent('connectx', {
 onEnter(args) {
  this.fd = args[0].toInt32();
  try {
   // Darwin sa_endpoints_t on arm64: destination sockaddr pointer at +24.
   const destination = args[1].add(24).readPointer();
   this.destination = decodeSockaddr(destination);
  } catch (error) {
   this.destination = 'decode-error: ' + error;
  }
  console.log('[CONNECTX] fd=' + this.fd + ' -> ' + this.destination);
 },
 onLeave(result) {
  console.log('[CONNECTX-RESULT] fd=' + this.fd + ' -> ' + this.destination +
   ' result=' + result.toInt32());
 }
});

const endpointGetHostnameAddress = Module.findGlobalExportByName('nw_endpoint_get_hostname');
const endpointGetPortAddress = Module.findGlobalExportByName('nw_endpoint_get_port');
if (endpointGetHostnameAddress !== null && endpointGetPortAddress !== null) {
 const endpointGetHostname = new NativeFunction(endpointGetHostnameAddress, 'pointer', ['pointer']);
 const endpointGetPort = new NativeFunction(endpointGetPortAddress, 'uint16', ['pointer']);

 attachIfPresent('nw_connection_create', {
  onEnter(args) {
   try {
    const hostnamePointer = endpointGetHostname(args[0]);
    const hostname = hostnamePointer.isNull() ? '<no-hostname>' : hostnamePointer.readUtf8String();
    console.log('[NW-CONNECTION] ' + hostname + ':' + endpointGetPort(args[0]));
   } catch (error) {
    console.log('[NW-CONNECTION] decode-error: ' + error);
   }
  }
 });
}

console.log('[+] iOS network tracing active');
