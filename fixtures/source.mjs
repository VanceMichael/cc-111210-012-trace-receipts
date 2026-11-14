import { listen } from '../src/http.mjs';
import { baseline, connectionReuse, interleavedTimestamps, multiInterface } from './scenarios.mjs';

// 保留原演练包的字节布局：6 个包、两个接口（微秒/纳秒）、乱序与重传。
const align = value => Math.ceil(value / 4) * 4;
function block(type, body) {
  const bytes = Buffer.alloc(12 + align(body.length));
  bytes.writeUInt32LE(type);
  bytes.writeUInt32LE(bytes.length, 4);
  body.copy(bytes, 8);
  bytes.writeUInt32LE(bytes.length, bytes.length - 4);
  return bytes;
}
function tcp(payload, sequence, reverse = false, flags = 0x18) {
  const bytes = Buffer.alloc(14 + 20 + 20 + Buffer.byteLength(payload));
  bytes.writeUInt16BE(0x0800, 12);
  bytes[14] = 0x45;
  bytes.writeUInt16BE(bytes.length - 14, 16);
  bytes[22] = 64;
  bytes[23] = 6;
  Buffer.from(reverse ? [192, 0, 2, 2] : [192, 0, 2, 1]).copy(bytes, 26);
  Buffer.from(reverse ? [192, 0, 2, 1] : [192, 0, 2, 2]).copy(bytes, 30);
  bytes.writeUInt16BE(reverse ? 80 : 45000, 34);
  bytes.writeUInt16BE(reverse ? 45000 : 80, 36);
  bytes.writeUInt32BE(sequence, 38);
  bytes[46] = 0x50;
  bytes[47] = flags;
  Buffer.from(payload).copy(bytes, 54);
  return bytes;
}
function packet(bytes, number, iface = 0) {
  const head = Buffer.alloc(20);
  head.writeUInt32LE(iface);
  head.writeUInt32LE(number * (iface === 1 ? 1_000_000 : 1_000), 8);
  head.writeUInt32LE(bytes.length, 12);
  head.writeUInt32LE(bytes.length, 16);
  return block(6, Buffer.concat([head, bytes, Buffer.alloc(align(bytes.length) - bytes.length)]));
}

/** 原有演练包：为了兼容既有测试，字节与包数保持不变。 */
export function trace() {
  const section = Buffer.from('4d3c2b1a01000000ffffffffffffffff', 'hex');
  const interfaceBody = Buffer.from('01000000ffff0000090001000600000000000000', 'hex');
  const nanoInterface = Buffer.from(interfaceBody);
  nanoInterface[12] = 9;
  const first = 'GET /a HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const second = 'GET /b HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const response = 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB';
  return Buffer.concat([
    block(0x0a0d0d0a, section),
    block(1, interfaceBody),
    block(1, nanoInterface),
    packet(tcp('', 100, false, 2), 1),
    packet(tcp(first.slice(15), 116), 3),
    packet(tcp(first.slice(0, 15), 101), 2),
    packet(tcp(first.slice(0, 15), 101), 4),
    packet(tcp(second, 101 + first.length), 5),
    packet(tcp(response, 501, true), 6, 1),
  ]);
}

/** 关联提取演练材料：默认用完整的 baseline 场景，也可按名称取其它场景。 */
export const scenes = {
  baseline: () => baseline().bytes,
  reuse: () => connectionReuse().bytes,
  interleaved: () => interleavedTimestamps().bytes,
  interfaces: () => multiInterface().bytes,
};

export async function startFixture() {
  return listen(async url => {
    if (url.pathname === '/trace.pcapng') return { type: 'application/octet-stream', body: trace() };
    const match = /^\/trace\/([a-z]+)\.pcapng$/.exec(url.pathname);
    if (match && scenes[match[1]]) return { type: 'application/octet-stream', body: scenes[match[1]]() };
    return { status: 404, body: {} };
  });
}
