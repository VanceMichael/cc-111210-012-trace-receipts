// 以太网 / IPv4 / TCP 只读解码。只处理已抓到的字节，不做校验和修复。
export function decodeFrame(data, linkType = 1) {
  if (linkType !== 1) return { supported: false, reason: `暂不支持的链路类型${linkType}` };
  if (data.length < 14) return { supported: false, reason: '以太网头截断' };
  let etherType = data.readUInt16BE(12);
  let offset = 14;
  // 只处理单个 802.1Q 标签；其余封装明确跳过。
  if (etherType === 0x8100 || etherType === 0x88a8) {
    if (data.length < 18) return { supported: false, reason: 'VLAN头截断' };
    etherType = data.readUInt16BE(16);
    offset = 18;
  }
  if (etherType !== 0x0800) return { supported: false, reason: '不是IPv4' };
  if (data.length < offset + 20) return { supported: false, reason: 'IPv4头截断' };
  const version = data[offset] >> 4;
  const ihl = (data[offset] & 15) * 4;
  if (version !== 4 || ihl < 20) return { supported: false, reason: 'IPv4头无效' };
  if (data.length < offset + ihl) return { supported: false, reason: 'IPv4选项截断' };
  const fragmentField = data.readUInt16BE(offset + 6);
  const fragmentOffset = fragmentField & 0x1fff;
  const moreFragments = (fragmentField & 0x2000) !== 0;
  if (fragmentOffset !== 0 || moreFragments) {
    return { supported: false, reason: 'IPv4分片未重组', fragmented: true };
  }
  if (data[offset + 9] !== 6) return { supported: false, reason: '不是TCP' };
  const totalLength = data.readUInt16BE(offset + 2);
  if (totalLength < ihl) return { supported: false, reason: 'IPv4总长度无效' };
  const ipEnd = offset + totalLength;
  const tcp = offset + ihl;
  if (data.length < tcp + 20) return { supported: false, reason: 'TCP头截断' };
  const tcpHeaderLength = (data[tcp + 12] >> 4) * 4;
  if (tcpHeaderLength < 20) return { supported: false, reason: 'TCP头长度无效' };
  const payloadStart = tcp + tcpHeaderLength;
  if (payloadStart > ipEnd) return { supported: false, reason: 'TCP头超出IPv4总长度' };
  const availableEnd = Math.min(ipEnd, data.length);
  const payloadEnd = Math.max(payloadStart, availableEnd);
  const payload = data.subarray(payloadStart, payloadEnd);
  return {
    supported: true,
    src: [data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]].join('.'),
    dst: [data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19]].join('.'),
    sport: data.readUInt16BE(tcp),
    dport: data.readUInt16BE(tcp + 2),
    seq: data.readUInt32BE(tcp + 4),
    ack: data.readUInt32BE(tcp + 8),
    flags: data[tcp + 13],
    syn: (data[tcp + 13] & 0x02) !== 0,
    ackFlag: (data[tcp + 13] & 0x10) !== 0,
    fin: (data[tcp + 13] & 0x01) !== 0,
    rst: (data[tcp + 13] & 0x04) !== 0,
    payload,
    payloadStart,
    payloadEnd,
    payloadTruncated: ipEnd > data.length,
  };
}
