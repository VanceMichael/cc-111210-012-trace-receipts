// 固定场景的合成抓包。每个函数返回 PCAPNG 字节与预期的包号说明。
// 场景覆盖需求中列出的边界：重传、乱序、半途开始、缺口、重叠冲突、连接重用、
// 流水线、100 Continue、分块正文、关闭定界响应、多接口时间分辨率、时间戳交错。

import { Recorder, tcpFrame } from './build.mjs';

const CLIENT = { src: '192.0.2.1', sport: 45000 };
const SERVER = { src: '192.0.2.2', sport: 80 };
const base = { src: CLIENT.src, dst: SERVER.src, sport: CLIENT.sport, dport: SERVER.sport };
const reverse = { src: SERVER.src, dst: CLIENT.src, sport: SERVER.sport, dport: CLIENT.sport };

const GET = target => `GET ${target} HTTP/1.1\r\nHost: gateway.test\r\n\r\n`;
const chunked = (...chunks) => {
  const encoded = chunks.map(chunk => `${chunk.length.toString(16)}\r\n${chunk}\r\n`).join('');
  return `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${encoded}0\r\n\r\n`;
};
const closeDelimited = body => `HTTP/1.1 200 OK\r\n\r\n${body}`;
const lengthBody = (body, status = '200 OK') => `HTTP/1.1 ${status}\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
const interim = () => 'HTTP/1.1 100 Continue\r\n\r\n';

/**
 * 乱序 + 重传 + 流水线 + 100 Continue + 分块 + 关闭定界。
 * 包序：SYN、a前半、a后半、a前半重传、b、全部响应、FIN。
 */
export function baseline() {
  const first = GET('/a');
  const second = GET('/b');
  const response = `${interim()}${chunked('OK')}${closeDelimited('tail')}`;
  const recorder = new Recorder({ interfaces: [{ tsresol: 6 }, { tsresol: 9 }] });
  const packets = {};
  packets.syn = recorder.add(tcpFrame({ ...base, payload: '', seq: 100, flags: 0x02 }), { time: 1_000 });
  packets.aHead = recorder.add(tcpFrame({ ...base, payload: first.slice(0, 15), seq: 101 }), { time: 2_000 });
  packets.aTail = recorder.add(tcpFrame({ ...base, payload: first.slice(15), seq: 116 }), { time: 3_000 });
  packets.aRetransmit = recorder.add(tcpFrame({ ...base, payload: first.slice(0, 15), seq: 101 }), { time: 4_000 });
  packets.b = recorder.add(tcpFrame({ ...base, payload: second, seq: 101 + first.length }), { time: 5_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: response, seq: 501 }), { interfaceId: 1, time: 6_000 });
  packets.fin = recorder.add(tcpFrame({ ...reverse, payload: '', seq: 501 + response.length, flags: 0x11 }), { interfaceId: 1, time: 7_000 });
  return { bytes: recorder.bytes(), packets, responseBytes: response.length, requestBytes: [first, second] };
}

/**
 * 请求方向有缺口：包只带 /a 的后半段，中间字节从未出现。
 * 预期：请求截断，不能拼成完整消息；缺口保留证据。
 */
export function requestGap() {
  const full = GET('/gap');
  const recorder = new Recorder();
  const packets = {};
  packets.head = recorder.add(tcpFrame({ ...base, payload: full.slice(0, 12), seq: 1000 }), { time: 1_000 });
  packets.tail = recorder.add(tcpFrame({ ...base, payload: full.slice(18), seq: 1018 }), { time: 2_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: lengthBody('X'), seq: 20 }), { time: 3_000 });
  return { bytes: recorder.bytes(), packets, missingBytes: 6 };
}

/**
 * 重叠冲突：两包声明同一序列号区间的不同字节。
 * 预期：冲突终止装配，保留先到字节与被拒字节。
 */
export function overlapConflict() {
  const first = 'GET /conflict HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const overlapping = 'GET /conflicX HTTP/1.1\r\nHost: gateway.test\r\n\r\n';
  const recorder = new Recorder();
  const packets = {};
  packets.original = recorder.add(tcpFrame({ ...base, payload: first, seq: 100 }), { time: 1_000 });
  packets.mutated = recorder.add(tcpFrame({ ...base, payload: overlapping, seq: 100 }), { time: 2_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: lengthBody('Y'), seq: 10 }), { time: 3_000 });
  return { bytes: recorder.bytes(), packets };
}

/**
 * 半途开始：没有 SYN，且首个请求只从请求行之后开始；随后是完整请求与响应。
 * 预期：连接标为 partialStart；残缺前缀重新同步后，完整请求仍能配对。
 */
export function midstreamStart() {
  const recorder = new Recorder();
  const packets = {};
  const cut = 'ost: gateway.test\r\n\r\n'; // 只有请求头部中段
  packets.fragment = recorder.add(tcpFrame({ ...base, payload: cut, seq: 900 }), { time: 1_000 });
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/late'), seq: 900 + cut.length }), { time: 2_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: lengthBody('Z'), seq: 30 }), { time: 3_000 });
  return { bytes: recorder.bytes(), packets, cutBytes: cut.length };
}

/**
 * 连接重用：同一四元组上先跑完一次请求/响应（关闭），再用新 SYN 重建。
 * 预期：两个世代，两对回执彼此不串。
 */
export function connectionReuse() {
  const recorder = new Recorder();
  const packets = {};
  const one = GET('/one');
  const responseOne = lengthBody('one');
  const two = GET('/two');
  const responseTwo = lengthBody('two');
  packets.syn1 = recorder.add(tcpFrame({ ...base, payload: '', seq: 100, flags: 0x02 }), { time: 1_000 });
  packets.get1 = recorder.add(tcpFrame({ ...base, payload: one, seq: 101, ack: 1 }), { time: 2_000 });
  packets.response1 = recorder.add(tcpFrame({ ...reverse, payload: responseOne, seq: 500, ack: 101 + one.length }), { time: 3_000 });
  packets.fin1 = recorder.add(tcpFrame({ ...reverse, payload: '', seq: 500 + responseOne.length, ack: 101 + one.length, flags: 0x11 }), { time: 4_000 });
  packets.syn2 = recorder.add(tcpFrame({ ...base, payload: '', seq: 7000, flags: 0x02 }), { time: 5_000 });
  packets.get2 = recorder.add(tcpFrame({ ...base, payload: two, seq: 7001, ack: 1 }), { time: 6_000 });
  packets.response2 = recorder.add(tcpFrame({ ...reverse, payload: responseTwo, seq: 9000, ack: 7001 + two.length }), { time: 7_000 });
  return { bytes: recorder.bytes(), packets, requests: [one, two], responses: [responseOne, responseTwo] };
}

/**
 * 时间戳交错：文件顺序把新世代的请求/响应写在旧世代回执之前，
 * 但时间戳和 SYN/序列号明确区分两个世代。
 * 预期：按观察时间归属后，旧回执配旧请求，新回执配新请求。
 */
export function interleavedTimestamps() {
  const recorder = new Recorder();
  const packets = {};
  const one = GET('/old');
  const responseOne = lengthBody('old');
  const two = GET('/new');
  const responseTwo = lengthBody('new');
  packets.syn1 = recorder.add(tcpFrame({ ...base, payload: '', seq: 100, flags: 0x02 }), { time: 1_000 });
  packets.get1 = recorder.add(tcpFrame({ ...base, payload: one, seq: 101, ack: 1 }), { time: 2_000 });
  packets.fin1 = recorder.add(tcpFrame({ ...reverse, payload: '', seq: 500, ack: 101 + one.length, flags: 0x11 }), { time: 4_000 });

  // 文件顺序：新世代先写，旧世代回执后写；时间戳保持真实次序。
  packets.syn2 = recorder.add(tcpFrame({ ...base, payload: '', seq: 7000, flags: 0x02 }), { time: 5_000 });
  packets.get2 = recorder.add(tcpFrame({ ...base, payload: two, seq: 7001, ack: 1 }), { time: 6_000 });
  packets.response2 = recorder.add(tcpFrame({ ...reverse, payload: responseTwo, seq: 9000, ack: 7001 + two.length }), { time: 7_000 });
  packets.response1 = recorder.add(tcpFrame({ ...reverse, payload: responseOne, seq: 500 + 0, ack: 101 + one.length }), { time: 3_000 });
  return { bytes: recorder.bytes(), packets, requests: [one, two], responses: [responseOne, responseTwo] };
}

/**
 * 缓存上限：请求正文远超给定上限，连接达到上限时终止，并给出原因。
 * 预期：终止原因 cache-limit，已并入的字节仍保留，但不丢旧字节后继续。
 */
export function cacheLimit(limitBytes = 2048) {
  const body = 'x'.repeat(limitBytes * 2);
  const upload = `POST /big HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const recorder = new Recorder();
  const packets = {};
  // 拆成多个 1024 字节的段，让预算在段边界处触发。
  const segments = [];
  for (let offset = 0, seq = 100; offset < upload.length; offset += 1024, seq += 1024) {
    const payload = upload.slice(offset, offset + 1024);
    segments.push(recorder.add(tcpFrame({ ...base, payload, seq }), { time: 1_000 + segments.length }));
  }
  packets.segments = segments;
  return { bytes: recorder.bytes(), packets, uploadBytes: upload.length };
}

/** 多接口与两种时间分辨率：同一连接分段落在不同接口上。 */
export function multiInterface() {
  const recorder = new Recorder({ interfaces: [
    { tsresol: 6, name: 'eth0' },
    { tsresol: 9, name: 'eth1' },
  ] });
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/multi'), seq: 101 }), { interfaceId: 0, time: 1_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: lengthBody('M'), seq: 501 }), { interfaceId: 1, time: 2_000 });
  return { bytes: recorder.bytes(), packets };
}

/** 截断响应：Content-Length 声明 10 字但只抓到 3 字，且没有连接关闭。 */
export function truncatedBody() {
  const recorder = new Recorder();
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/short'), seq: 100 }), { time: 1_000 });
  packets.partial = recorder.add(tcpFrame({ ...reverse, payload: 'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc', seq: 500 }), { time: 2_000 });
  return { bytes: recorder.bytes(), packets };
}

/** 关闭定界且已见 FIN：正文可判定完整；对照无 FIN 的情况。 */
export function closeDelimitedWithFin() {
  const recorder = new Recorder();
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/close'), seq: 100 }), { time: 1_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: closeDelimited('body-until-fin'), seq: 500 }), { time: 2_000 });
  packets.fin = recorder.add(tcpFrame({ ...reverse, payload: '', seq: 500 + closeDelimited('body-until-fin').length, flags: 0x11 }), { time: 3_000 });
  return { bytes: recorder.bytes(), packets };
}

/** 关闭定界但抓包未见 FIN：只能记为截断（capture-ended）。 */
export function closeDelimitedNoFin() {
  const recorder = new Recorder();
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/open'), seq: 100 }), { time: 1_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: closeDelimited('body-no-fin'), seq: 500 }), { time: 2_000 });
  return { bytes: recorder.bytes(), packets };
}

export function emptyCapture() {
  const recorder = new Recorder();
  return { bytes: recorder.bytes(), packets: {} };
}

/** snaplen 截断：包内 IP 总长度声明完整，但只抓到了前半段字节。 */
export function snaplenTruncated() {
  const request = GET('/snap');
  const recorder = new Recorder();
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: request, seq: 100 }), { time: 1_000, captured: 14 + 20 + 20 + 8 });
  return { bytes: recorder.bytes(), packets, declared: request.length, captured: 8 };
}

/**
 * 完全逆序到达：先收到请求尾部，再收到头部；响应同样逆序分段。
 * 预期：向前并入后仍得到完整请求/回执，重复字节只入账一次。
 */
export function reversedSegments() {
  const first = GET('/reverse');
  const response = lengthBody('R');
  const recorder = new Recorder();
  const packets = {};
  packets.tail = recorder.add(tcpFrame({ ...base, payload: first.slice(12), seq: 112 }), { time: 1_000 });
  packets.head = recorder.add(tcpFrame({ ...base, payload: first.slice(0, 12), seq: 100 }), { time: 2_000 });
  packets.responseTail = recorder.add(tcpFrame({ ...reverse, payload: response.slice(10), seq: 510 }), { time: 3_000 });
  packets.responseHead = recorder.add(tcpFrame({ ...reverse, payload: response.slice(0, 10), seq: 500 }), { time: 4_000 });
  return { bytes: recorder.bytes(), packets, requestLength: first.length, responseLength: response.length };
}

/**
 * POST 请求带正文与流水线：两个请求先后到达，响应顺序返回。
 * 预期：请求正文按 Content-Length 切分，第二个请求不会吞并第一个的正文。
 */
export function pipelinedPosts() {
  const first = 'POST /one HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: 5\r\n\r\nAAAAA';
  const second = 'POST /two HTTP/1.1\r\nHost: gateway.test\r\nContent-Length: 3\r\n\r\nBBB';
  const recorder = new Recorder();
  const packets = {};
  packets.requests = recorder.add(tcpFrame({ ...base, payload: first + second, seq: 100 }), { time: 1_000 });
  packets.response = recorder.add(tcpFrame({ ...reverse, payload: lengthBody('1') + lengthBody('2'), seq: 500 }), { time: 2_000 });
  return { bytes: recorder.bytes(), packets, first, second };
}

/**
 * 1xx 中间响应后最终响应缺失：请求收到 100 Continue 但没有最终回执。
 * 预期：配对状态为 final-missing，中间响应作为无主证据保留。
 */
export function interimOnly() {
  const recorder = new Recorder();
  const packets = {};
  packets.request = recorder.add(tcpFrame({ ...base, payload: GET('/continue'), seq: 100 }), { time: 1_000 });
  packets.interim = recorder.add(tcpFrame({ ...reverse, payload: interim(), seq: 500 }), { time: 2_000 });
  return { bytes: recorder.bytes(), packets };
}
