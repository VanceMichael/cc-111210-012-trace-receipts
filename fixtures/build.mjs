// 测试用的 PCAPNG 与 TCP/HTTP 合成器。只生成内存字节，不访问网络。
//
// 说明：为了精确控制序列号、包序、接口和时间分辨率，这里直接拼装链路层字节。
// 生成的数据仅用于本地演练，不含真实个人资料。

const align = value => Math.ceil(value / 4) * 4;

export function block(type, body) {
  const bytes = Buffer.alloc(12 + align(body.length));
  bytes.writeUInt32LE(type, 0);
  bytes.writeUInt32LE(bytes.length, 4);
  body.copy(bytes, 8);
  bytes.writeUInt32LE(bytes.length, bytes.length - 4);
  return bytes;
}

/** IDB：linkType=1、snapLen、if_tsresol（code 9）。tsoffset 可选。 */
export function interfaceBlock({ tsresol = 6, tsoffset = 0n, name } = {}) {
  const options = [];
  const option = (code, value) => {
    const padded = align(value.length);
    const bytes = Buffer.alloc(4 + padded);
    bytes.writeUInt16LE(code, 0);
    bytes.writeUInt16LE(value.length, 2);
    value.copy(bytes, 4);
    options.push(bytes);
  };
  option(9, Buffer.from([tsresol]));
  if (tsoffset !== 0n) {
    const value = Buffer.alloc(8);
    value.writeBigInt64LE(tsoffset);
    option(14, value);
  }
  if (name) option(2, Buffer.from(name));
  const end = Buffer.alloc(4);
  const header = Buffer.alloc(8);
  header.writeUInt16LE(1, 0);      // LINKTYPE_ETHERNET
  header.writeUInt32LE(65535, 4);  // snaplen
  return block(1, Buffer.concat([header, ...options, end]));
}

export function sectionBlock() {
  return block(0x0a0d0d0a, Buffer.from('4d3c2b1a01000000ffffffffffffffff', 'hex'));
}

/**
 * 以太网/IPv4/TCP 帧。
 * flags 默认 0x18（PSH+ACK）。payload 用 Buffer 或字符串。
 */
export function tcpFrame({
  src = '192.0.2.1', dst = '192.0.2.2', sport = 45000, dport = 80,
  seq = 1, ack = 0, flags = 0x18, payload = '', vlan = null,
} = {}) {
  const payloadBytes = Buffer.from(payload, 'latin1');
  const ethernet = vlan === null ? 14 : 18;
  const bytes = Buffer.alloc(ethernet + 20 + 20 + payloadBytes.length);
  if (vlan === null) {
    bytes.writeUInt16BE(0x0800, 12);
  } else {
    bytes.writeUInt16BE(0x8100, 12);
    bytes.writeUInt16BE(vlan, 14);
    bytes.writeUInt16BE(0x0800, 16);
  }
  bytes[ethernet] = 0x45;
  bytes[ethernet + 1] = 0;
  bytes.writeUInt16BE(bytes.length - ethernet, ethernet + 2);
  bytes[ethernet + 8] = 64;
  bytes[ethernet + 9] = 6;
  const sourceIp = src.split('.').map(Number);
  const destinationIp = dst.split('.').map(Number);
  Buffer.from(sourceIp).copy(bytes, ethernet + 12);
  Buffer.from(destinationIp).copy(bytes, ethernet + 16);
  const tcp = ethernet + 20;
  bytes.writeUInt16BE(sport, tcp);
  bytes.writeUInt16BE(dport, tcp + 2);
  bytes.writeUInt32BE(seq >>> 0, tcp + 4);
  bytes.writeUInt32BE(ack >>> 0, tcp + 8);
  bytes[tcp + 12] = 0x50;
  bytes[tcp + 13] = flags;
  payloadBytes.copy(bytes, tcp + 20);
  return bytes;
}

/** EPB：接口号、时间 tick（64 位由 high/low 组成）、可选注释选项。 */
export function enhancedPacket(frame, { interfaceId = 0, ticks = 0n, comment = null } = {}) {
  const options = [];
  if (comment !== null) {
    const value = Buffer.from(comment, 'utf8');
    const bytes = Buffer.alloc(4 + align(value.length));
    bytes.writeUInt16LE(1, 0);
    bytes.writeUInt16LE(value.length, 2);
    value.copy(bytes, 4);
    options.push(bytes);
  }
  const end = Buffer.alloc(4);
  const header = Buffer.alloc(20);
  header.writeUInt32LE(interfaceId, 0);
  header.writeUInt32LE(Number((ticks >> 32n) & 0xffffffffn), 4);
  header.writeUInt32LE(Number(ticks & 0xffffffffn), 8);
  header.writeUInt32LE(frame.length, 12);
  header.writeUInt32LE(frame.length, 16);
  return block(6, Buffer.concat([header, frame, Buffer.alloc(align(frame.length) - frame.length), ...options, end]));
}

/** 把多块拼成一个文件；任何块尾长度不符都能被查看器拒绝。 */
export function capture(...parts) {
  return Buffer.concat(parts);
}

/**
 * 记录包号：按写入顺序从 1 开始，用于断言证据回溯。
 * 时间以纳秒给出，按接口的 if_tsresol 转换成该接口的 64 位 tick。
 */
export class Recorder {
  constructor({ interfaces = [{ tsresol: 6 }] } = {}) {
    this.parts = [sectionBlock(), ...interfaces.map(iface => interfaceBlock(iface))];
    this.packetCount = 0;
    this.interfaces = interfaces;
    this.packets = [];
  }

  ticksFor(interfaceId, nanoseconds) {
    const tsresol = this.interfaces[interfaceId]?.tsresol ?? 6;
    const value = BigInt(Math.round(nanoseconds));
    if (tsresol & 0x80) return (value << BigInt(tsresol & 0x7f)) / 1_000_000_000n;
    return value * 10n ** BigInt(tsresol) / 1_000_000_000n;
  }

  add(frame, { interfaceId = 0, time = 0, comment = null, captured = frame.length } = {}) {
    this.packetCount += 1;
    // captured < frame.length 模拟 snaplen 截断：IP 总长度仍声明完整值。
    const stored = frame.subarray(0, captured);
    const packet = enhancedPacket(stored, { interfaceId, ticks: this.ticksFor(interfaceId, time), comment });
    const offset = this.parts.reduce((sum, part) => sum + part.length, 0);
    this.parts.push(packet);
    this.packets.push({ number: this.packetCount, offset, length: stored.length + 28, declaredLength: frame.length });
    return this.packetCount;
  }

  bytes() {
    return capture(...this.parts);
  }
}
