import test from 'node:test';
import assert from 'node:assert/strict';
import { ByteStream, ByteBudget, seqDiff, seqAdd } from '../src/stream.mjs';
import { parseBlocks } from '../src/pcapng.mjs';
import { parseCapture } from '../src/pcapng.mjs';
import { decodeFrame } from '../src/frame.mjs';
import { resolution, timestampToNanoseconds, nanoString, proof } from '../src/util.mjs';
import { analyzeCapture } from '../src/analyze.mjs';
import * as scenarios from '../fixtures/scenarios.mjs';
import { Recorder, sectionBlock, interfaceBlock, tcpFrame, enhancedPacket } from '../fixtures/build.mjs';

test('序列号差在 2^32 回绕时保持前后关系', () => {
  assert.equal(seqDiff(5, 0xffff_fffe), 7);
  assert.equal(seqDiff(0xffff_fffe, 5), -7);
  assert.equal(seqAdd(0xffff_ffff, 2), 1);
  assert.equal(seqDiff(0, 0x8000_0000), -0x8000_0000);
});

test('向前重叠与向后重叠都允许，重复字节只入账一次', () => {
  const stream = new ByteStream({ direction: 'test' });
  const base = 0xffff_ff00;
  // 先到中段，再到末尾，再到开头；全部相邻但顺序颠倒。
  assert.equal(stream.offer(segment('CDE', base + 2, 1)), 3);
  assert.equal(stream.offer(segment('EFGH', base + 4, 2)), 3); // 首字节 E 重复，新增 FGH
  assert.equal(stream.offer(segment('AB', base, 3)), 2);
  assert.equal(stream.prefix.toString(), 'ABCDEFGH');
  assert.equal(stream.base, base);
  assert.equal(stream.duplicateBytes, 1);
  assert.deepEqual(stream.gaps.filter(gap => gap.state === 'open'), []);
});

test('缺口未补齐时不越过缺口拼接', () => {
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment('AB', 100, 1));
  stream.offer(segment('EF', 104, 2));
  assert.equal(stream.prefix.toString(), 'AB');
  assert.equal(stream.pending.length, 1);
  const gaps = stream.gaps.filter(gap => gap.state === 'open');
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].startSequence, 102);
  assert.equal(gaps[0].endSequence, 104);
  assert.equal(gaps[0].length, 2);
});

test('缺口补齐后按序并入，并标记 filled', () => {
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment('AB', 100, 1));
  stream.offer(segment('EF', 104, 2));
  stream.offer(segment('CD', 102, 3));
  assert.equal(stream.prefix.toString(), 'ABCDEF');
  assert.equal(stream.gaps[0].state, 'filled');
  assert.equal(stream.gaps[0].filledPacket, 3);
});

test('重叠内容冲突终止装配并保留先到与被拒字节', () => {
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment('ABCD', 100, 7));
  stream.offer(segment('ABXD', 100, 8));
  assert.equal(stream.prefix.toString(), 'ABCD');
  assert.equal(stream.terminated.reason, 'conflict');
  assert.equal(stream.conflicts.length, 1);
  const conflict = stream.conflicts[0];
  assert.equal(conflict.atSequence, 100);
  assert.equal(conflict.keptPackets[0], 7);
  assert.equal(conflict.rejectedPacket, 8);
  assert.equal(conflict.kept.toString(), 'ABCD'.slice(0, 64));
  assert.equal(conflict.rejected.toString(), 'ABXD'.slice(0, 64));
  // 终止后不再接受任何字节。
  assert.equal(stream.offer(segment('ZZ', 104, 9)), 0);
});

test('暂存区内的重复字节去重、冲突同样终止', () => {
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment('AB', 100, 1));
  stream.offer(segment('DEF', 104, 2));
  stream.offer(segment('DEF', 104, 3));
  assert.equal(stream.pending.length, 1);
  assert.equal(stream.duplicateBytes, 3);
  stream.offer(segment('DZF', 104, 4));
  assert.equal(stream.terminated.reason, 'conflict');
});

test('缓存上限按连接共享预算，达到后终止且不丢旧字节继续', () => {
  const budget = new ByteBudget(8);
  const stream = new ByteStream({ direction: 'test', budget });
  assert.equal(stream.offer(segment('ABCD', 100, 1)), 4);
  assert.equal(stream.offer(segment('EFGH', 104, 2)), 4);
  // 下一条会超过预算：必须终止，而不是丢掉 ABCD 继续。
  assert.equal(stream.offer(segment('IJ', 108, 3)), 0);
  assert.equal(stream.terminated.reason, 'cache-limit');
  assert.equal(stream.prefix.toString(), 'ABCDEFGH');
  assert.equal(budget.used, 8);
});

test('待并片段数量上限也以明确原因终止', () => {
  const stream = new ByteStream({ direction: 'test', segmentLimit: 2 });
  stream.offer(segment('A', 100, 1));
  stream.offer(segment('C', 102, 2));
  stream.offer(segment('D', 103, 3));
  stream.offer(segment('E', 104, 4));
  assert.equal(stream.terminated.reason, 'cache-limit');
  assert.equal(stream.prefix.toString(), 'A');
});

test('接口时间分辨率：十进制与二进制都换算成纳秒', () => {
  const micro = resolution(6);
  assert.equal(timestampToNanoseconds(0, 2_000, micro), 2_000_000);
  const nano = resolution(9);
  assert.equal(timestampToNanoseconds(0, 2_000, nano), 2_000);
  const binary = resolution(0x80 | 10); // 2^-10 秒
  assert.equal(timestampToNanoseconds(0, 1024, binary), 1_000_000_000);
  assert.equal(nanoString(1_000_000_000), '1.000000000');
  assert.throws(() => resolution(20), /分辨率无效/);
});

test('PCAPNG 读取每接口 tsresol 与 tsoffset', () => {
  const recorder = new Recorder({ interfaces: [{ tsresol: 6 }, { tsresol: 9, tsoffset: 5n, name: 'eth1' }] });
  recorder.add(tcpFrame({ payload: '', seq: 1 }), { interfaceId: 0, time: 1_000_000 });
  recorder.add(tcpFrame({ payload: '', seq: 1 }), { interfaceId: 1, time: 2_000_000 });
  const capture = parseCapture(recorder.bytes());
  assert.equal(capture.interfaces.length, 2);
  assert.equal(capture.interfaces[0].tsresol, 6);
  assert.equal(capture.interfaces[1].tsresol, 9);
  assert.equal(capture.interfaces[1].tsoffset, 5n);
  assert.equal(capture.interfaces[1].name, 'eth1');
  assert.equal(capture.packets[0].nanoseconds, 1_000_000);
  assert.equal(capture.packets[1].nanoseconds, 2_000_000 + 5_000_000_000);
});

test('块尾长度不符直接拒绝', () => {
  const recorder = new Recorder();
  recorder.add(tcpFrame({ payload: 'x', seq: 1 }));
  const bytes = recorder.bytes();
  const bad = Buffer.from(bytes);
  bad.writeUInt32LE(9999, bad.length - 4);
  assert.throws(() => parseBlocks(bad), /尾部长度不一致/);
  assert.throws(() => parseBlocks(bytes.subarray(0, bytes.length - 1)), /长度无效/);
});

test('IPv4 分片不参与关联并留作跳过证据', () => {
  const recorder = new Recorder();
  const frame = tcpFrame({ payload: 'GET / HTTP/1.1\r\n\r\n', seq: 1 });
  frame[14 + 6] = 0x20; // MF 位置 1
  recorder.add(frame, { time: 1_000 });
  const result = analyzeCapture(recorder.bytes());
  assert.equal(result.capture.decoded, 0);
  assert.equal(result.skipped[0].reason, 'IPv4分片未重组');
});

test('证据回指接口、包号、帧内与文件字节偏移', () => {
  const { bytes, packets } = scenarios.baseline();
  const result = analyzeCapture(bytes);
  const exchange = result.connections[0].exchanges[0];
  const evidence = exchange.request.evidence;
  assert.equal(evidence.length, 2);
  assert.equal(evidence[0].packetNumber, packets.aHead);
  assert.equal(evidence[1].packetNumber, packets.aTail);
  assert.equal(evidence[0].interfaceId, 0);
  assert.equal(evidence[0].frameOffset[0], 54);
  // 文件偏移 = EPB 起点 + 20 字节 EPB 头 + 8 字节块头 + 帧内偏移。
  const capture = parseCapture(bytes);
  const packet = capture.packets[packets.aHead - 1];
  assert.equal(evidence[0].fileOffset[0], packet.blockOffset + 28 + 54);
  assert.equal(evidence[0].sequence[0], 101);
  assert.equal(evidence[1].sequence[1], 140);
});

test('proof 把换行显式化，截断时标明总字节数', () => {
  assert.equal(proof(Buffer.from('a\r\nb')), 'a\\r\\nb');
  assert.match(proof(Buffer.from('x'.repeat(10)), 4), /^xxxx…\(10字节\)$/);
});

function segment(text, seq, packetNumber) {
  return {
    seq, data: Buffer.from(text, 'latin1'), packetNumber, interfaceId: 0,
    frameOffset: 54, blockOffset: 0, timestamp: 1,
  };
}
