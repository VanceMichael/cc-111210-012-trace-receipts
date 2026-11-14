import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCapture } from '../src/analyze.mjs';
import { parseMessage } from '../src/http-message.mjs';
import { MessageReader } from '../src/messages.mjs';
import { ByteStream } from '../src/stream.mjs';
import { Recorder, tcpFrame } from '../fixtures/build.mjs';
import * as scenarios from '../fixtures/scenarios.mjs';

test('请求与响应按流水线顺序配对，100 Continue 挂在第一个请求上', () => {
  const result = analyzeCapture(scenarios.baseline().bytes);
  const connection = result.connections[0];
  assert.equal(connection.generation, 1);
  assert.equal(connection.exchanges.length, 2);
  const [first, second] = connection.exchanges;
  assert.equal(first.request.startLine.target, '/a');
  assert.equal(first.response.startLine.status, 200);
  assert.equal(first.interim.length, 1);
  assert.equal(first.interim[0].startLine.status, 100);
  assert.equal(first.response.framing.mode, 'chunked');
  assert.equal(first.responseKind, 'complete');
  assert.equal(second.request.startLine.target, '/b');
  assert.equal(second.response.startLine.status, 200);
  assert.deepEqual(second.interim, []);
  assert.equal(second.responseKind, 'complete');
  assert.equal(result.summary.sequenceGaps, 0);
  assert.equal(result.summary.overlapConflicts, 0);
});

test('同一字节的重传只入账一次且不改变装配结果', () => {
  const result = analyzeCapture(scenarios.baseline().bytes);
  const upstream = result.connections[0].directions.clientToServer;
  assert.equal(upstream.assembledBytes, 78);
  assert.equal(upstream.receivedBytes, 93);
  assert.equal(upstream.duplicateBytes, 15);
  assert.deepEqual(upstream.gaps, []);
});

test('逆序分段仍可向前并成完整消息', () => {
  const result = analyzeCapture(scenarios.reversedSegments().bytes);
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.request.startLine.target, '/reverse');
  assert.equal(exchange.responseKind, 'complete');
  assert.equal(exchange.response.startLine.status, 200);
  assert.equal(result.connections[0].directions.clientToServer.gaps.length, 0);
});

test('流水线 POST 正文按 Content-Length 切分', () => {
  const result = analyzeCapture(scenarios.pipelinedPosts().bytes);
  const exchanges = result.connections[0].exchanges;
  assert.equal(exchanges.length, 2);
  assert.equal(exchanges[0].request.startLine.target, '/one');
  assert.equal(exchanges[0].request.framing.mode, 'length');
  assert.equal(exchanges[0].request.framing.length, 5);
  assert.equal(exchanges[0].request.bodyBytes, 5);
  assert.equal(exchanges[1].request.startLine.target, '/two');
  assert.equal(exchanges[1].request.bodyBytes, 3);
  assert.equal(result.summary.unattached, 0);
});

test('请求缺口保留证据，不拼出看似完整的请求', () => {
  const result = analyzeCapture(scenarios.requestGap().bytes);
  const connection = result.connections[0];
  assert.equal(connection.exchanges.length, 0);
  const gap = connection.directions.clientToServer.gaps[0];
  assert.equal(gap.length, 6);
  assert.equal(gap.state, 'open');
  assert.equal(gap.beforePacket, scenesPacket(scenarios.requestGap(), 'head'));
  assert.equal(gap.afterPacket, scenesPacket(scenarios.requestGap(), 'tail'));
  assert.match(gap.proofBefore, /^GET \/gap HTT/);
  assert.match(gap.proofAfter, /^\\nHost/);
  const request = connection.unattachedMessages.find(item => item.role === 'request');
  assert.equal(request.state, 'head-incomplete');
  assert.equal(request.complete, false);
  assert.equal(result.summary.sequenceGaps, 1);
  assert.ok(result.fragments.some(item => item.kind === 'sequence-gap'));
  assert.ok(result.fragments.some(item => item.kind === 'unassembled-segment'));
});

test('重叠冲突终止装配并保留被拒字节证据', () => {
  const result = analyzeCapture(scenarios.overlapConflict().bytes);
  const firstKept = 'GET /conflict HTTP/1.1\\r\\nHost: gateway.test\\r\\n\\r\\n';
  const firstRejected = 'GET /conflicX HTTP/1.1\\r\\nHost: gateway.test\\r\\n\\r\\n';
  const connection = result.connections[0];
  const conflict = connection.directions.clientToServer.conflicts[0];
  assert.equal(connection.directions.clientToServer.terminated.reason, 'conflict');
  assert.equal(conflict.keptPackets[0], 1);
  assert.equal(conflict.rejectedPacket, 2);
  assert.equal(conflict.length, 46);
  assert.equal(conflict.kept, firstKept);
  assert.equal(conflict.rejected, firstRejected);
  // 冲突发生在请求行，但先到字节仍是完整请求；回执与先到字节配对，被拒字节单独列出。
  assert.equal(result.fragments.some(item => item.kind === 'overlap-conflict'), true);
});

test('半途开始：不可解析前缀重新同步，之后的完整请求仍能配对', () => {
  const result = analyzeCapture(scenarios.midstreamStart().bytes);
  const connection = result.connections[0];
  assert.equal(connection.partialStart, true);
  assert.equal(connection.exchanges.length, 1);
  assert.equal(connection.exchanges[0].request.startLine.target, '/late');
  assert.equal(connection.exchanges[0].responseKind, 'complete');
  const skipped = connection.unattachedMessages.find(item => item.state === 'unparsable-prefix');
  assert.ok(skipped);
  assert.equal(skipped.role, 'request');
  assert.equal(skipped.byteRange.text, '0x0-0x15');
});

test('连接重用产生两个世代，回执不串', () => {
  const result = analyzeCapture(scenarios.connectionReuse().bytes);
  assert.equal(result.connections.length, 2);
  const [first, second] = result.connections;
  assert.equal(first.generation, 1);
  assert.equal(second.generation, 2);
  assert.equal(second.supersedes, 1);
  assert.equal(first.exchanges.length, 1);
  assert.equal(second.exchanges.length, 1);
  assert.equal(first.exchanges[0].request.startLine.target, '/one');
  assert.equal(first.exchanges[0].response.startLine.services ?? first.exchanges[0].response.bodyPreview, 'one');
  assert.equal(second.exchanges[0].request.startLine.target, '/two');
  assert.equal(second.exchanges[0].response.bodyPreview, 'two');
});

test('时间戳交错时按观察时间归属，旧回执不配给新请求', () => {
  const result = analyzeCapture(scenarios.interleavedTimestamps().bytes);
  assert.equal(result.connections.length, 2);
  const [first, second] = result.connections;
  assert.equal(first.exchanges[0].request.startLine.target, '/old');
  assert.equal(first.exchanges[0].response.bodyPreview, 'old');
  assert.equal(second.exchanges[0].request.startLine.target, '/new');
  assert.equal(second.exchanges[0].response.bodyPreview, 'new');
  for (const connection of result.connections) {
    for (const exchange of connection.exchanges) {
      assert.equal(exchange.order.responseAfterRequest, true);
    }
  }
});

test('截断响应与请求配对但标为 truncated，正文不足的证据保留', () => {
  const result = analyzeCapture(scenarios.truncatedBody().bytes);
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.responseKind, 'truncated');
  assert.equal(exchange.response.complete, false);
  assert.equal(exchange.response.reason, 'body-truncated');
  assert.equal(exchange.response.framing.mode, 'length');
  assert.equal(exchange.response.framing.length, 10);
  assert.equal(exchange.response.bodyBytes, 3);
  assert.equal(result.summary.truncatedResponses, 1);
});

test('关闭定界：见到 FIN 才判完整，无 FIN 只能记为截断', () => {
  const withFin = analyzeCapture(scenarios.closeDelimitedWithFin().bytes);
  const exchange = withFin.connections[0].exchanges[0];
  assert.equal(exchange.responseKind, 'complete');
  assert.equal(exchange.response.framing.mode, 'close');
  assert.equal(exchange.response.bodyPreview, 'body-until-fin');
  assert.equal(withFin.connections[0].directions.serverToClient.finAt !== null, true);

  const withoutFin = analyzeCapture(scenarios.closeDelimitedNoFin().bytes);
  const open = withoutFin.connections[0].exchanges[0];
  assert.equal(open.responseKind, 'truncated');
  assert.equal(open.response.complete, false);
  assert.equal(open.response.reason, 'capture-ended');
  assert.equal(withoutFin.summary.truncatedResponses, 1);
});

test('只有 100 Continue 没有最终回执时，请求标为 final-missing', () => {
  const result = analyzeCapture(scenarios.interimOnly().bytes);
  const connection = result.connections[0];
  assert.equal(connection.exchanges.length, 0);
  const request = connection.unattachedMessages.find(item => item.role === 'request');
  assert.equal(request.state, 'final-missing');
  const interim = connection.unattachedMessages.find(item => item.role === 'interim');
  assert.equal(interim.startLine.status, 100);
});

test('每个回执都能回到接口、包号与字节区间', () => {
  const { bytes, packets } = scenarios.baseline();
  const result = analyzeCapture(bytes);
  const exchange = result.connections[0].exchanges[0];
  for (const side of [exchange.request, exchange.response]) {
    assert.ok(side.evidence.length >= 1);
    for (const piece of side.evidence) {
      assert.ok(piece.packetNumber >= 1);
      assert.ok([0, 1].includes(piece.interfaceId));
      assert.equal(piece.fileOffset[0] < piece.fileOffset[1], true);
    }
  }
  assert.equal(exchange.response.evidence[0].interfaceId, 1);
  assert.equal(exchange.response.evidence[0].packetNumber, packets.response);
});

test('缓存上限终止该方向并给出原因，已装配字节保留', () => {
  const { bytes } = scenarios.cacheLimit(2048);
  const result = analyzeCapture(bytes, { connectionCacheBytes: 2048 });
  const connection = result.connections[0];
  const upstream = connection.directions.clientToServer;
  assert.equal(upstream.terminated.reason, 'cache-limit');
  assert.equal(upstream.assembledBytes, 2048);
  assert.equal(connection.cache.usedBytes, 2048);
  assert.ok(result.fragments.some(item => item.kind === 'stream-termination' && item.reason === 'cache-limit'));
  // 不能因为终止就悄悄输出一条完整请求。
  assert.equal(connection.exchanges.length, 0);
});

test('同一连接落在不同接口时证据保留各自接口与分辨率', () => {
  const { bytes, packets } = scenarios.multiInterface();
  const result = analyzeCapture(bytes);
  assert.equal(result.capture.interfaces[0].tsresol, 6);
  assert.equal(result.capture.interfaces[0].name, 'eth0');
  assert.equal(result.capture.interfaces[1].tsresol, 9);
  assert.equal(result.capture.interfaces[1].name, 'eth1');
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.request.evidence[0].interfaceId, 0);
  assert.equal(exchange.response.evidence[0].interfaceId, 1);
  assert.equal(result.connections[0].interfaces.includes(0) && result.connections[0].interfaces.includes(1), true);
});

test('HTTP 边界解析拒绝有歧义的定界方式', () => {
  const conflict = parseMessage(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc'), 0, { kind: 'response' });
  assert.equal(conflict.complete, false);
  assert.equal(conflict.reason, 'framing-invalid');
  const malformed = parseMessage(Buffer.from('HTTP/1.1 2000 OK\r\n\r\n'), 0, { kind: 'response' });
  assert.equal(malformed.reason, 'malformed-head');
  const chunkMissing = parseMessage(Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab'), 0, { kind: 'response' });
  assert.equal(chunkMissing.reason, 'chunk-incomplete');
});

function segment(text, seq, packetNumber) {
  return { seq, data: Buffer.from(text, 'latin1'), packetNumber, interfaceId: 0, frameOffset: 54, blockOffset: 0, timestamp: 1 };
}

function scenesPacket(scenario, key) {
  return scenario.packets[key];
}

test('snaplen 截断终止装配并留证，不把半截负载当完整字节', () => {
  const result = analyzeCapture(scenarios.snaplenTruncated().bytes);
  const connection = result.connections[0];
  assert.equal(connection.truncatedFrames, 1);
  assert.equal(connection.directions.clientToServer.terminated.reason, 'capture-truncated');
  assert.equal(connection.directions.clientToServer.assembledBytes, 8);
  assert.equal(connection.exchanges.length, 0);
  assert.ok(result.fragments.some(item => item.kind === 'stream-termination' && item.reason === 'capture-truncated'));
});

test('无包空抓包不产生连接或错误分类', () => {
  const result = analyzeCapture(scenarios.emptyCapture().bytes);
  assert.equal(result.connections.length, 0);
  assert.equal(result.fragments.length, 0);
  assert.equal(result.capture.packetCount, 0);
  assert.equal(result.summary.exchanges, 0);
});

test('多接口包号全局唯一，同接口内仍为文件顺序', () => {
  const { bytes, packets } = scenarios.multiInterface();
  const result = analyzeCapture(bytes);
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.request.evidence[0].packetNumber, packets.request);
  assert.equal(exchange.response.evidence[0].packetNumber, packets.response);
  assert.notEqual(packets.request, packets.response);
});

test('新世代 SYN 之后才到的旧世代回执仍归旧世代', () => {
  const up = { src: '192.0.2.1', dst: '192.0.2.2', sport: 45000, dport: 80 };
  const down = { src: '192.0.2.2', dst: '192.0.2.1', sport: 80, dport: 45000 };
  const one = 'GET /one HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const two = 'GET /two HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const recorder = new Recorder();
  recorder.add(tcpFrame({ ...up, payload: '', seq: 100, flags: 0x02 }), { time: 1_000 });
  recorder.add(tcpFrame({ ...up, payload: one, seq: 101 }), { time: 2_000 });
  recorder.add(tcpFrame({ ...up, payload: '', seq: 101 + one.length, flags: 0x11 }), { time: 3_000 });
  recorder.add(tcpFrame({ ...up, payload: '', seq: 5_000, flags: 0x02 }), { time: 4_000 });
  recorder.add(tcpFrame({ ...up, payload: two, seq: 5_001 }), { time: 5_000 });
  // 旧世代的回执晚于新 SYN 到达，但序列号/ACK 属于旧世代。
  recorder.add(tcpFrame({ ...down, payload: 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none', seq: 700, ack: 101 + one.length }), { time: 6_000 });
  recorder.add(tcpFrame({ ...down, payload: 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo', seq: 9_000, ack: 5_001 + two.length }), { time: 7_000 });

  const result = analyzeCapture(recorder.bytes());
  assert.equal(result.connections.length, 2);
  const [first, second] = result.connections;
  assert.equal(first.exchanges[0].request.startLine.target, '/one');
  assert.equal(first.exchanges[0].response.bodyPreview, 'one');
  assert.equal(second.exchanges[0].request.startLine.target, '/two');
  assert.equal(second.exchanges[0].response.bodyPreview, 'two');
  assert.equal(result.summary.missingResponses, 0);
});

test('暂存区重叠：后到的更早片段被拆分保留，不误报冲突', () => {
  // 先到 [2,6)，再到 [0,4)：重叠区 [2,4) 一致，前段 [0,2) 应保留。
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment('CDEF', 102, 1));
  // 前缀为空（base=102），先到片段直接成为前缀；随后 0 偏移的包覆盖前缀并向前扩展。
  stream.offer(segment('ABCD', 100, 2));
  assert.equal(stream.terminated, null);
  assert.equal(stream.prefix.toString(), 'ABCDEF');
});

test('暂存区重叠：不一致的重叠必须终止而非拼出完整消息', () => {
  const full = 'GET /m HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  // 构造两个互不覆盖的暂存片段，再注入一个与它们间重叠不一致的片段。
  const stream = new ByteStream({ direction: 'test' });
  stream.offer(segment(full.slice(0, 5), 1, 1));     // 前缀 GET /
  stream.offer(segment(full.slice(10, 20), 11, 2));  // 暂存（缺口 6..10）
  stream.offer(segment(full.slice(12, 18), 13, 3));  // 与暂存重叠
  assert.equal(stream.terminated, null);
  stream.offer(segment('Y', 13, 4));                 // 不同字节
  assert.equal(stream.terminated?.reason, 'conflict');
});

test('RST 关闭的定长响应标为截断并注明关闭方式', () => {
  const up = { src: '192.0.2.1', dst: '192.0.2.2', sport: 45000, dport: 80 };
  const down = { src: '192.0.2.2', dst: '192.0.2.1', sport: 80, dport: 45000 };
  const recorder = new Recorder();
  recorder.add(tcpFrame({ ...up, payload: 'GET /r HTTP/1.1\r\nHost: gateway.test\r\n\r\n', seq: 1 }), { time: 1_000 });
  recorder.add(tcpFrame({ ...down, payload: 'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc', seq: 1 }), { time: 2_000 });
  recorder.add(tcpFrame({ ...down, payload: '', seq: 655, flags: 0x14 }), { time: 3_000 });
  const result = analyzeCapture(recorder.bytes());
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.responseKind, 'truncated');
  assert.equal(exchange.response.reason, 'body-truncated');
  assert.match(exchange.response.detail, /RST/);
});

test('chunked 尾部字段被正确跳过，消息完整', () => {
  const up = { src: '192.0.2.1', dst: '192.0.2.2', sport: 45000, dport: 80 };
  const down = { src: '192.0.2.2', dst: '192.0.2.1', sport: 80, dport: 45000 };
  const recorder = new Recorder();
  recorder.add(tcpFrame({ ...up, payload: 'GET /c HTTP/1.1\r\nHost: gateway.test\r\n\r\n', seq: 1 }), { time: 1_000 });
  recorder.add(tcpFrame({ ...down, payload: 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n', seq: 1, flags: 0x11 }), { time: 2_000 });
  const result = analyzeCapture(recorder.bytes());
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.responseKind, 'complete');
  assert.equal(exchange.response.chunkCount, 1);
  assert.equal(exchange.response.bodyBytes, 23); // 含 chunk 长度行与尾部字段的原始正文区
  assert.equal(exchange.response.chunkPayloadBytes, 3);
});

test('请求同时带 Transfer-Encoding 与 Content-Length 时拒绝定界', () => {
  const up = { src: '192.0.2.1', dst: '192.0.2.2', sport: 45000, dport: 80 };
  const recorder = new Recorder();
  recorder.add(tcpFrame({ ...up, payload: 'POST /smuggle HTTP/1.1\r\nHost: gateway.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n', seq: 1 }), { time: 1_000 });
  const result = analyzeCapture(recorder.bytes());
  const request = result.connections[0].unattachedMessages.find(item => item.role === 'request');
  assert.equal(request.complete, false);
  assert.equal(request.reason, 'framing-invalid');
  assert.match(request.detail, /同时出现/);
});

test('跨接口不同时间精度：量化误差不把有效回执误判为早于请求', () => {
  const up = { src: '192.0.2.1', dst: '192.0.2.2', sport: 45000, dport: 80 };
  const down = { src: '192.0.2.2', dst: '192.0.2.1', sport: 80, dport: 45000 };
  const recorder = new Recorder({ interfaces: [
    { tsresol: 6 },
    { tsresol: 9 },
    { tsresol: 0x80 | 10 }, // 2^-10 秒 ≈ 0.98 毫秒
  ] });
  const request = 'GET /precision HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  recorder.add(tcpFrame({ ...up, payload: request.slice(0, 10), seq: 1 }), { interfaceId: 0, time: 1_000_000 });
  recorder.add(tcpFrame({ ...up, payload: request.slice(10), seq: 11 }), { interfaceId: 1, time: 1_000_001 });
  recorder.add(tcpFrame({ ...down, payload: 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc', seq: 1 }), { interfaceId: 2, time: 1_000_002 });

  const result = analyzeCapture(recorder.bytes());
  assert.equal(result.capture.interfaces[2].binaryTimestamp, true);
  const exchange = result.connections[0].exchanges[0];
  assert.equal(exchange.request.startLine.target, '/precision');
  assert.equal(exchange.responseKind, 'complete');
  assert.equal(exchange.order.responseAfterRequest, true);
  assert.ok(exchange.order.toleranceNanoseconds > 0);
  assert.equal(exchange.request.evidence[0].interfaceId, 0);
  assert.equal(exchange.response.evidence[0].interfaceId, 2);
});
