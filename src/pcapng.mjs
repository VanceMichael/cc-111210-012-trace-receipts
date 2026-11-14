// 解析脱敏 PCAPNG：区块、接口（含 if_tsresol/if_tsoffset）、增强包、以及随包给出的选项。
// 只读取本地 Buffer，不访问网络。

import { timestampToNanoseconds, resolution } from './util.mjs';

export function parseBlocks(bytes) {
  const blocks = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) throw new Error(`抓包块截断：偏移${offset}剩余${bytes.length - offset}字节`);
    const type = bytes.readUInt32LE(offset);
    const size = bytes.readUInt32LE(offset + 4);
    if (size < 12 || size % 4 || offset + size > bytes.length) throw new Error(`抓包块长度无效：偏移${offset}`);
    if (bytes.readUInt32LE(offset + size - 4) !== size) throw new Error(`抓包块尾部长度不一致：偏移${offset}`);
    blocks.push({ type, offset, size, body: bytes.subarray(offset + 8, offset + size - 4) });
    offset += size;
  }
  return blocks;
}

function readOptions(body, offset = 0) {
  const options = [];
  let cursor = offset;
  while (cursor + 4 <= body.length) {
    const code = body.readUInt16LE(cursor);
    const length = body.readUInt16LE(cursor + 2);
    if (code === 0 || length === 0 || cursor + 4 + length > body.length) break;
    options.push({ code, value: body.subarray(cursor + 4, cursor + 4 + length) });
    cursor += 4 + Math.ceil(length / 4) * 4;
  }
  return options;
}

function parseInterface(body) {
  if (body.length < 8) throw new Error('接口描述块截断');
  const linkType = body.readUInt16LE(0);
  const snapLength = body.readUInt32LE(4);
  let tsresol = 6;
  let tsoffset = 0n;
  let name;
  for (const option of readOptions(body, 8)) {
    if (option.code === 2) name = option.value.toString('utf8');
    if (option.code === 9 && option.value.length === 1) tsresol = option.value[0];
    if (option.code === 14 && option.value.length === 8) tsoffset = option.value.readBigInt64LE(0);
  }
  return { linkType, snapLength, tsresol, tsoffset, name };
}

/** IDB 之后的 EPB 只使用其所在分段的接口表。 */
export function parseCapture(bytes) {
  const blocks = parseBlocks(bytes);
  const interfaces = [];
  const packets = [];
  const anchor = [];
  let sectionStart = 0;
  for (const block of blocks) {
    if (block.type === 0x0a0d0d0a) {
      interfaces.length = 0;
      const bom = block.body.length >= 4 ? block.body.readUInt32LE(0) : 0x1a2b3c4d;
      if (bom !== 0x1a2b3c4d) throw new Error('仅支持小端PCAPNG');
      if (block.body.length >= 16) {
        anchor.push({
          section: sectionStart,
          blockOffset: block.offset,
          sectionLength: Number(block.body.readBigInt64LE(8)),
          note: '节头块提供的抓包时间下界不具备可验证义务，仅记录',
        });
      }
      sectionStart = block.offset;
      continue;
    }
    if (block.type === 1) {
      interfaces.push(parseInterface(block.body));
      continue;
    }
    if (block.type === 6) {
      const body = block.body;
      if (body.length < 20) throw new Error(`增强包块截断：偏移${block.offset}`);
      const interfaceId = body.readUInt32LE(0);
      if (!interfaces[interfaceId]) throw new Error(`未知接口${interfaceId}：偏移${block.offset}`);
      const captured = body.readUInt32LE(12);
      if (20 + captured > body.length) throw new Error(`增强包抓取长度越界：偏移${block.offset}`);
      const tsHigh = body.readUInt32LE(4);
      const tsLow = body.readUInt32LE(8);
      const iface = interfaces[interfaceId];
      const res = resolution(iface.tsresol);
      // if_tsoffset 以秒为单位加到时间戳上。
      const nanoseconds = timestampToNanoseconds(tsHigh, tsLow, res)
        + Number(iface.tsoffset) * 1_000_000_000;
      let flags = null;
      for (const option of readOptions(body, 20 + Math.ceil(captured / 4) * 4)) {
        if (option.code === 2 && option.value.length >= 1) flags = option.value.readUInt32LE(0);
      }
      packets.push({
        interfaceId,
        blockOffset: block.offset,
        timestampRaw: (BigInt(tsHigh) << 32n) | BigInt(tsLow),
        nanoseconds,
        // 该接口一个 tick 的纳秒数：用于比较不同接口时间戳时的量化误差。
        tickNanoseconds: res.tickNanoseconds,
        captured,
        comment: flags,
        data: body.subarray(20, 20 + captured),
      });
      continue;
    }
    // 其它块（如简单包、名称解析）不参与 HTTP 关联。
  }
  return { interfaces, packets, anchor };
}
