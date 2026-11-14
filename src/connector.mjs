// 兼容原有查看器：块校验、包块头读取，以及新增的 HTTP 请求/回执关联提取。

import { get } from './http.mjs';
import { parseBlocks } from './pcapng.mjs';
import { analyzeCapture } from './analyze.mjs';

/** 原有行为：只做 PCAPNG 块校验和以太网/IPv4/TCP 头读取。 */
export function blocks(bytes) {
  return parseBlocks(bytes);
}

export function packetHeader(body) {
  if (body.length < 20) throw new Error('包块截断');
  const captured = body.readUInt32LE(12);
  const packet = body.subarray(20, 20 + captured);
  if (packet.length < 54 || packet.readUInt16BE(12) !== 0x0800 || packet[23] !== 6) throw new Error('不是IPv4 TCP包');
  const ipSize = (packet[14] & 15) * 4;
  const tcp = 14 + ipSize;
  const tcpSize = (packet[tcp + 12] >> 4) * 4;
  if (tcpSize < 20 || tcp + tcpSize > packet.length) throw new Error('TCP头截断');
  return {
    interfaceId: body.readUInt32LE(0),
    timestampLow: body.readUInt32LE(8),
    source: [...packet.subarray(26, 30)].join('.'),
    destination: [...packet.subarray(30, 34)].join('.'),
    sourcePort: packet.readUInt16BE(tcp),
    destinationPort: packet.readUInt16BE(tcp + 2),
    sequence: packet.readUInt32BE(tcp + 4),
    flags: packet[tcp + 13],
    payload: packet.subarray(tcp + tcpSize).toString('latin1'),
  };
}

/** 原有查看器入口：包块、包头和数量。 */
export async function inspect(base) {
  const bytes = Buffer.from(await (await get(base, '/trace.pcapng')).arrayBuffer());
  const items = blocks(bytes);
  return {
    bytes: bytes.length,
    blocks: items.map(({ type, offset, size }) => ({ type, offset, size })),
    packets: items.filter(item => item.type === 6).length,
    headers: items.filter(item => item.type === 6).map(item => packetHeader(item.body)),
  };
}

/** 新的关联提取入口：解析、装配、切分并配对 HTTP/1.1 消息。 */
export async function extract(base, options = {}) {
  const trace = options.trace ?? '/trace.pcapng';
  if (!/^\/(?:trace(?:\/[a-z]+)?)\.pcapng$/.test(trace)) throw new Error('演练路径无效');
  const bytes = Buffer.from(await (await get(base, trace)).arrayBuffer());
  const { trace: _trace, ...analysisOptions } = options;
  return analyzeCapture(bytes, analysisOptions);
}

export { analyzeCapture };
