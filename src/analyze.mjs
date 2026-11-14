// 抓包整体分析：分接口解码、按四元组和连接世代组织连接、装配字节流、切分 HTTP 并配对。
// 全部输入来自本地字节；本模块不做任何网络访问。
//
// 世代判定：同一四元组上的新 SYN（不含 ACK）开启新世代；普通包则依据 ACK 号与
// 已知序列号空间归属到某个世代，避免旧世代迟到的回执被拼到新世代。

import { parseCapture } from './pcapng.mjs';
import { decodeFrame } from './frame.mjs';
import { ByteStream, ByteBudget } from './stream.mjs';
import { MessageReader, summarizeMessage, messageEvidence } from './messages.mjs';
import { seqAdd, seqDiff, proof, hexRange } from './util.mjs';

export const DEFAULTS = {
  connectionCacheBytes: 8 * 1024 * 1024,
  segmentLimit: 4096,
};

/** 按纳秒时间戳排序；相同时间保留文件顺序，结果可重复。 */
function timeOrder(packets) {
  return packets
    .map((packet, index) => ({ packet, index }))
    .sort((a, b) => a.packet.nanoseconds - b.packet.nanoseconds || a.index - b.index)
    .map(entry => entry.packet);
}

function endpointKey(endpoint) {
  return `${endpoint.ip}:${endpoint.port}`;
}

function orient(frame) {
  const a = { ip: frame.src, port: frame.sport };
  const b = { ip: frame.dst, port: frame.dport };
  if (frame.syn && !frame.ackFlag) return { client: a, server: b };
  if (frame.syn && frame.ackFlag) return { client: b, server: a };
  // 未看到 SYN 时以端口大小推测：低端口侧通常是服务端。
  // 两侧端口相同时以较小地址侧为服务端，仍然可重复。
  if (a.port === b.port) {
    return a.ip <= b.ip ? { client: a, server: b } : { client: b, server: a };
  }
  return a.port > b.port ? { client: a, server: b } : { client: b, server: a };
}

function containsSeq(seq, range) {
  if (!range) return false;
  return seqDiff(seq, range.start) >= 0 && seqDiff(seq, range.end) <= 0;
}

function rangeContains(seq, length, range) {
  if (!range) return false;
  return containsSeq(seq, range) && containsSeq(seqAdd(seq, length), range);
}

function updateRange(side, seq, length) {
  if (!side.range) side.range = { start: seq, end: seqAdd(seq, length) };
  else {
    if (seqDiff(seq, side.range.start) < 0) side.range.start = seq;
    if (seqDiff(seqAdd(seq, length), side.range.end) > 0) side.range.end = seqAdd(seq, length);
  }
}

export function analyzeCapture(bytes, options = {}) {
  const settings = { ...DEFAULTS, ...options };
  const capture = parseCapture(bytes);
  const decoded = [];
  const skipped = [];

  for (const [order, packet] of capture.packets.entries()) {
    // 包号按文件顺序全局计数，跨接口仍可唯一定位；接口号单独记录。
    const number = order + 1;
    const iface = capture.interfaces[packet.interfaceId];
    const frame = decodeFrame(packet.data, iface.linkType);
    if (!frame.supported) {
      skipped.push({
        order,
        interfaceId: packet.interfaceId,
        packetNumber: number,
        blockOffset: packet.blockOffset,
        reason: frame.reason,
        fragmented: frame.fragmented ?? false,
      });
      continue;
    }
    decoded.push({
      order,
      interfaceId: packet.interfaceId,
      packetNumber: number,
      blockOffset: packet.blockOffset,
      nanoseconds: packet.nanoseconds,
      tickNanoseconds: packet.tickNanoseconds,
      captured: packet.captured,
      frame,
    });
  }

  const generationsByKey = new Map();
  const generations = [];

  for (const packet of timeOrder(decoded)) {
    const frame = packet.frame;
    const oriented = orient(frame);
    const key = `${endpointKey(oriented.client)}>${endpointKey(oriented.server)}`;
    let list = generationsByKey.get(key);
    if (!list) {
      list = [];
      generationsByKey.set(key, list);
    }

    const opens = frame.syn && !frame.ackFlag
      && frame.src === oriented.client.ip && frame.sport === oriented.client.port;
    let generation;

    if (opens) {
      const previous = list.at(-1);
      // SYN 重传：同一初始序列号且上一世代尚未关闭时，仍属于同一世代。
      const sameIsn = previous && previous.clientIsn !== undefined
        && seqDiff(frame.seq, previous.clientIsn) === 0 && !previous.closed;
      if (!sameIsn) {
        generation = createGeneration(key, oriented, packet, { generation: list.length + 1, partial: false, cacheBytes: settings.connectionCacheBytes });
        if (previous) previous.closed = { reason: 'replaced-by-syn', timestamp: packet.nanoseconds };
        generation.supersedes = previous ? previous.generation : null;
        list.push(generation);
        generations.push(generation);
        generation.clientIsn = frame.seq;
      } else {
        generation = previous;
      }
    } else {
      generation = selectGeneration(list, frame, oriented);
      if (!generation) {
        generation = createGeneration(key, oriented, packet, { generation: list.length + 1, partial: true, cacheBytes: settings.connectionCacheBytes });
        list.push(generation);
        generations.push(generation);
      }
    }

    const direction = frame.src === generation.client.ip && frame.sport === generation.client.port
      ? 'upstream' : 'downstream';
    const side = generation[direction];
    const segmentLength = frame.payload.length + (frame.syn ? 1 : 0) + (frame.fin ? 1 : 0);

    side.frames.push({
      interfaceId: packet.interfaceId,
      packetNumber: packet.packetNumber,
      blockOffset: packet.blockOffset,
      nanoseconds: packet.nanoseconds,
      order: packet.order,
      sequence: frame.seq,
      sequenceEnd: seqAdd(frame.seq, segmentLength),
      payloadLength: frame.payload.length,
      payloadStart: frame.payloadStart,
      payloadEnd: frame.payloadEnd,
      flags: frame.flags,
      syn: frame.syn,
      ack: frame.ackFlag,
      fin: frame.fin,
      rst: frame.rst,
      payloadTruncated: frame.payloadTruncated,
    });
    updateRange(side, frame.seq, segmentLength);
    generation.interfaceIds.add(packet.interfaceId);
    generation.lastTimestamp = Math.max(generation.lastTimestamp ?? packet.nanoseconds, packet.nanoseconds);
    generation.lastPacket = packet.packetNumber;
    if (frame.rst) {
      generation.reset = true;
      generation.closed = { reason: 'rst', timestamp: packet.nanoseconds };
      side.resetAt = packet.nanoseconds;
    }
    if (frame.fin) {
      side.finAt = packet.nanoseconds;
      if (direction === 'downstream') generation.closed = generation.closed ?? { reason: 'fin', timestamp: packet.nanoseconds };
    }

    if (frame.payload.length > 0) {
      side.stream.offer({
        seq: frame.seq,
        data: frame.payload,
        packetNumber: packet.packetNumber,
        interfaceId: packet.interfaceId,
        frameOffset: frame.payloadStart,
        blockOffset: packet.blockOffset,
        timestamp: packet.nanoseconds,
        tickNanoseconds: packet.tickNanoseconds,
      });
      if (frame.payloadTruncated) {
        // 抓取长度不足：已抓到的字节作为证据并入，但必须终止该方向，
        // 避免把半截 TCP 负载当作完整字节继续装配。
        generation.truncatedFrames = (generation.truncatedFrames ?? 0) + 1;
        side.stream.terminate(
          'capture-truncated',
          `包${packet.packetNumber}的TCP负载被snaplen截断（已抓${frame.payload.length}字节）`,
          seqAdd(frame.seq, frame.payload.length),
        );
      }
    }
  }

  const reports = generations.map(generation => reportGeneration(generation, settings));
  const fragments = [];
  for (const report of reports) {
    for (const segment of report.unassociatedSegments) {
      fragments.push({
        kind: 'unassembled-segment',
        connection: { key: report.key, generation: report.generation },
        ...segment,
      });
    }
    for (const item of report.unattachedMessages) {
      const incomplete = item.state === 'head-incomplete' || item.state === 'body-truncated'
        || item.state === 'chunk-incomplete' || item.state === 'trailer-incomplete'
        || item.state === 'chunk-line-invalid' || item.state === 'chunk-terminator-invalid'
        || item.state === 'chunk-limit' || item.state === 'trailer-limit'
        || item.state === 'framing-invalid' || item.state === 'header-limit'
        || item.state === 'request-incomplete' || item.state === 'truncated'
        || item.state === 'final-missing' || item.state === 'capture-ended'
        || item.state === 'connection-reset' || item.state === 'parser-stalled'
        || item.state === 'malformed-head' || item.state === 'truncated-unassociated';
      fragments.push({
        kind: incomplete ? 'incomplete-message' : 'unattached-message',
        connection: { key: report.key, generation: report.generation },
        role: item.role,
        direction: item.direction,
        state: item.state,
        complete: item.complete,
        packetNumbers: item.evidence.map(piece => piece.packetNumber),
        streamRange: item.byteRange.text,
        reason: item.reason,
        detail: item.detail,
      });
    }
    for (const gap of [...report.directions.clientToServer.gaps, ...report.directions.serverToClient.gaps]) {
      fragments.push({
        connection: { key: report.key, generation: report.generation },
        direction: report.directions.clientToServer.gaps.includes(gap) ? 'client-to-server' : 'server-to-client',
        ...gap,
        kind: 'sequence-gap',
        gapKind: gap.kind,
      });
    }
    for (const sideName of ['clientToServer', 'serverToClient']) {
      for (const conflict of report.directions[sideName].conflicts) {
        fragments.push({
          kind: 'overlap-conflict',
          connection: { key: report.key, generation: report.generation },
          direction: sideName === 'clientToServer' ? 'client-to-server' : 'server-to-client',
          ...conflict,
        });
      }
      const termination = report.directions[sideName].terminated;
      if (termination) {
        fragments.push({
          kind: 'stream-termination',
          connection: { key: report.key, generation: report.generation },
          direction: sideName === 'clientToServer' ? 'client-to-server' : 'server-to-client',
          ...termination,
        });
      }
    }
  }
  for (const item of skipped) {
    fragments.push({ kind: 'skipped-frame', ...item });
  }

  const summary = summarizeReports(reports);
  return {
    capture: {
      bytes: bytes.length,
      interfaces: capture.interfaces.map((iface, id) => ({
        id,
        name: iface.name ?? null,
        linkType: iface.linkType,
        snapLength: iface.snapLength,
        tsresol: iface.tsresol,
        binaryTimestamp: (iface.tsresol & 0x80) !== 0,
        tsoffset: String(iface.tsoffset),
      })),
      packetCount: capture.packets.length,
      decoded: decoded.length,
    },
    summary,
    ledger: buildLedger(reports),
    connections: reports,
    skipped,
    fragments,
  };
}

/** 便于实施同事整理“哪些请求确实收到了回复”的简明账目。 */
function buildLedger(reports) {
  const entries = [];
  for (const report of reports) {
    for (const exchange of report.exchanges) {
      const requestLine = exchange.request.startLine;
      entries.push({
        connection: report.key,
        generation: report.generation,
        method: requestLine?.method ?? null,
        target: requestLine?.target ?? null,
        status: exchange.response.startLine?.status ?? null,
        interimStatuses: exchange.interim.map(item => item.startLine?.status ?? null),
        reply: exchange.responseKind,
        requestPackets: exchange.request.evidence.map(piece => piece.packetNumber),
        responsePackets: exchange.response.evidence.map(piece => piece.packetNumber),
      });
    }
    for (const item of report.unattachedMessages) {
      const requestLine = item.role === 'request' ? item.startLine : null;
      entries.push({
        connection: report.key,
        generation: report.generation,
        method: requestLine?.method ?? null,
        target: requestLine?.target ?? null,
        status: item.role === 'response' ? item.startLine?.status ?? null : null,
        interimStatuses: [],
        reply: item.state,
        role: item.role,
        requestPackets: item.role === 'request' ? item.evidence.map(piece => piece.packetNumber) : [],
        responsePackets: item.role === 'response' ? item.evidence.map(piece => piece.packetNumber) : [],
      });
    }
  }
  return entries;
}

function summarizeReports(reports) {
  const summary = {
    connections: reports.length,
    exchanges: 0,
    completeResponses: 0,
    truncatedResponses: 0,
    missingResponses: 0,
    unattached: 0,
    unassociatedSegments: 0,
    sequenceGaps: 0,
    overlapConflicts: 0,
    terminatedStreams: 0,
  };
  for (const report of reports) {
    summary.exchanges += report.exchanges.length;
    for (const exchange of report.exchanges) {
      if (exchange.responseKind === 'complete') summary.completeResponses += 1;
      else summary.truncatedResponses += 1;
    }
    summary.unattached += report.unattachedMessages.length;
    summary.unassociatedSegments += report.unassociatedSegments.length;
    summary.sequenceGaps += report.directions.clientToServer.gaps.length + report.directions.serverToClient.gaps.length;
    summary.overlapConflicts += report.directions.clientToServer.conflicts.length + report.directions.serverToClient.conflicts.length;
    summary.terminatedStreams += (report.directions.clientToServer.terminated ? 1 : 0)
      + (report.directions.serverToClient.terminated ? 1 : 0);
    summary.missingResponses += report.unattachedMessages.filter(item => item.role === 'request').length;
  }
  return summary;
}

function createGeneration(key, oriented, packet, { generation, partial, cacheBytes }) {
  const budget = new ByteBudget(cacheBytes);
  return {
    key,
    client: oriented.client,
    server: oriented.server,
    generation,
    supersedes: null,
    partial,
    startPacket: packet.packetNumber,
    startTimestamp: packet.nanoseconds,
    lastTimestamp: packet.nanoseconds,
    lastPacket: packet.packetNumber,
    interfaceIds: new Set([packet.interfaceId]),
    reset: false,
    closed: null,
    truncatedFrames: 0,
    budget,
    upstream: newSide('client-to-server', budget),
    downstream: newSide('server-to-client', budget),
  };
}

function newSide(direction, budget) {
  return {
    direction,
    stream: new ByteStream({ direction, budget }),
    frames: [],
    range: null,
    finAt: null,
    resetAt: null,
  };
}

function selectGeneration(list, frame, oriented) {
  if (!list.length) return null;
  const matches = [];
  for (const generation of list) {
    const direction = frame.src === generation.client.ip && frame.sport === generation.client.port ? 'upstream' : 'downstream';
    const same = generation[direction].range;
    const other = generation[direction === 'upstream' ? 'downstream' : 'upstream'].range;
    let strong = false;
    const segmentLength = frame.payload.length + (frame.syn ? 1 : 0) + (frame.fin ? 1 : 0);
    if (same && rangeContains(frame.seq, segmentLength, same)) strong = true;
    if (frame.ackFlag && other && containsSeq(frame.ack, other)) strong = true;
    matches.push({ generation, strong });
  }
  const strong = matches.filter(item => item.strong);
  if (strong.length) return strong.at(-1).generation;
  // 没有序列号证据时，用观察时间贴近度挑选世代；绝不无条件回落到最新世代。
  const open = list.filter(generation => !generation.closed);
  if (!open.length) return null;
  let best = null;
  for (const generation of open) {
    const distance = Math.abs(frame.nanoseconds - generation.lastTimestamp);
    if (!best || distance < best.distance || (distance === best.distance && generation.generation > best.generation.generation)) {
      best = { generation, distance };
    }
  }
  return best.generation;
}

function reportGeneration(generation, settings) {
  // 缓存上限按连接计，同时约束两个方向。
  generation.budget.limit = settings.connectionCacheBytes;
  for (const side of [generation.upstream, generation.downstream]) {
    side.stream.limit = settings.connectionCacheBytes;
    if (side.stream.segmentLimit > settings.segmentLimit) side.stream.segmentLimit = settings.segmentLimit;
  }
  const upstreamClose = { kind: generation.upstream.resetAt !== null ? 'rst' : generation.upstream.finAt !== null ? 'fin' : null };
  const downstreamClose = { kind: generation.downstream.resetAt !== null ? 'rst' : generation.downstream.finAt !== null ? 'fin' : null };
  const requests = new MessageReader(generation.upstream.stream, 'request', upstreamClose);
  const requestMessages = requests.all();

  // 响应侧的 HEAD 语义取决于对应请求的方法；只有完整请求才消耗响应。
  const headMethods = requestMessages.filter(request => request.complete).map(request => request.head?.start?.method ?? null);
  const responses = [];
  const reader = new MessageReader(generation.downstream.stream, 'response', downstreamClose);
  generation.upstream.reader = requests;
  generation.downstream.reader = reader;
  let finalOrdinal = 0;
  while (!reader.done) {
    const message = reader.next(headMethods[finalOrdinal] ?? null);
    if (!message) break;
    responses.push(message);
    if (message.complete && !message.interim) finalOrdinal += 1;
  }

  const pairing = pairMessages(requestMessages, responses, {
    requests: requestMessages.map(message => messageTimestamp(message, generation.upstream.stream)),
    responses: responses.map(message => messageTimestamp(message, generation.downstream.stream)),
  });
  const unattachedMessages = [];
  const exchanges = [];

  for (const entry of pairing.entries) {
    if (entry.state === 'paired') {
      const requestTimestamp = messageTimestamp(entry.request, generation.upstream.stream);
      const responseTimestamp = messageTimestamp(entry.response, generation.downstream.stream);
      exchanges.push({
        state: 'paired',
        request: summarizeMessage(entry.request, generation.upstream.stream),
        interim: entry.interim.map(message => summarizeMessage(message, generation.downstream.stream)),
        response: summarizeMessage(entry.response, generation.downstream.stream),
        responseKind: entry.response.complete ? 'complete' : 'truncated',
        closeKind: downstreamClose.kind,
        interimAmbiguous: entry.interimAmbiguous,
        order: {
          requestTimestamp: requestTimestamp?.nanoseconds ?? null,
          responseTimestamp: responseTimestamp?.nanoseconds ?? null,
          // 不同接口的时间精度不同，留出量化误差后再判断先后。
          toleranceNanoseconds: tolerance(requestTimestamp, responseTimestamp),
          responseAfterRequest: responseAfter(requestTimestamp, responseTimestamp),
        },
      });
    } else {
      if (entry.request) {
        unattachedMessages.push({
          role: 'request',
          direction: 'client-to-server',
          state: entry.state,
          ...summarizeMessage(entry.request, generation.upstream.stream),
        });
      }
      for (const message of entry.interim) {
        unattachedMessages.push({
          role: 'interim',
          direction: 'server-to-client',
          state: entry.state,
          ...summarizeMessage(message, generation.downstream.stream),
        });
      }
    }
  }
  for (const response of responses) {
    if (!response.paired && !response.interimUsed) {
      unattachedMessages.push({
        role: 'response',
        direction: 'server-to-client',
        state: response.precedesRequest ? 'precedes-request' : response.complete ? 'request-missing' : 'truncated-unassociated',
        ...summarizeMessage(response, generation.downstream.stream),
      });
    }
  }
  for (const side of [['client-to-server', generation.upstream], ['server-to-client', generation.downstream]]) {
    for (const skipped of side[1].reader.skipped) {
      unattachedMessages.push({
        role: side[0] === 'client-to-server' ? 'request' : 'response',
        direction: side[0],
        state: skipped.reason,
        complete: false,
        index: null,
        startLine: null,
        headers: null,
        byteRange: {
          streamStart: skipped.start,
          headEnd: skipped.end,
          bodyStart: skipped.end,
          bodyEnd: skipped.end,
          length: skipped.end - skipped.start,
          text: hexRange(skipped.start, skipped.end),
        },
        bodyBytes: 0,
        bodyPreview: proof(side[1].stream.prefix.subarray(skipped.start, skipped.end), 64) || null,
        chunkCount: null,
        headPreview: null,
        evidence: messageEvidence(side[1].stream, { streamStart: skipped.start, headEnd: skipped.end, bodyStart: skipped.end, bodyEnd: skipped.end }),
      });
    }
  }

  const terminations = [
    ['client-to-server', generation.upstream.stream.terminated],
    ['server-to-client', generation.downstream.stream.terminated],
  ].filter(([, value]) => value).map(([direction, value]) => ({ direction, ...value }));

  return {
    key: generation.key,
    generation: generation.generation,
    supersedes: generation.supersedes,
    partialStart: generation.partial,
    client: endpointKey(generation.client),
    server: endpointKey(generation.server),
    startPacket: generation.startPacket,
    startTimestamp: generation.startTimestamp,
    lastPacket: generation.lastPacket,
    lastTimestamp: generation.lastTimestamp,
    interfaces: [...generation.interfaceIds].sort((a, b) => a - b),
    reset: generation.reset,
    closed: generation.closed,
    truncatedFrames: generation.truncatedFrames,
    cache: {
      limitBytes: settings.connectionCacheBytes,
      usedBytes: generation.budget.used,
      terminated: terminations.length > 0 ? terminations[0] : null,
    },
    directions: {
      clientToServer: sideReport(generation.upstream),
      serverToClient: sideReport(generation.downstream),
    },
    exchanges,
    unattachedMessages,
    unassociatedSegments: [
      ...generation.upstream.stream.unassembledSegments().map(item => ({ direction: 'client-to-server', ...item })),
      ...generation.downstream.stream.unassembledSegments().map(item => ({ direction: 'server-to-client', ...item })),
    ],
  };
}

function messageTimestamp(message, stream) {
  if (!message) return null;
  const evidence = stream.evidenceFor(message.streamStart, Math.max(message.streamStart + 1, message.headEnd));
  if (!evidence.length) return null;
  // 取消息头部首个字节所在包的观察时间与量化精度。
  return { nanoseconds: evidence[0].timestamp, precision: evidence[0].tickNanoseconds ?? 1 };
}

/** 两端时间戳各自可能是量化后的值；给出合起来的容差。 */
function tolerance(request, response) {
  if (!request || !response) return 0;
  // 两端各有一个 tick 的量化误差。
  return (request.precision ?? 1) + (response.precision ?? 1);
}

function responseAfter(request, response) {
  if (!request || !response) return null;
  return response.nanoseconds + tolerance(request, response) >= request.nanoseconds;
}

function sideReport(side) {
  const stream = side.stream;
  return {
    direction: side.direction,
    frames: side.frames.length,
    payloadBytes: side.frames.reduce((sum, frame) => sum + frame.payloadLength, 0),
    assembledBytes: stream.length,
    receivedBytes: stream.receivedBytes,
    duplicateBytes: stream.duplicateBytes,
    baseSequence: stream.base,
    endSequence: stream.endSequence,
    range: side.range,
    terminated: stream.terminated,
    gaps: stream.gaps.map(gap => ({
      kind: gap.kind,
      startSequence: gap.startSequence,
      endSequence: gap.endSequence,
      length: seqDiff(gap.endSequence, gap.startSequence),
      state: gap.state,
      beforePacket: gap.beforePacket ?? null,
      afterPacket: gap.afterPacket ?? null,
      filledPacket: gap.filledPacket ?? null,
      proofBefore: proof(gap.proofBefore ?? Buffer.alloc(0), 48),
      proofAfter: proof(gap.proofAfter ?? Buffer.alloc(0), 48),
    })),
    conflicts: stream.conflicts.map(conflict => ({
      atSequence: conflict.atSequence,
      length: conflict.length,
      keptPackets: conflict.keptPackets,
      rejectedPacket: conflict.rejectedPacket,
      rejectedInterfaceId: conflict.rejectedInterfaceId ?? null,
      rejectedFrameOffset: conflict.rejectedFrameOffset ?? null,
      kept: proof(conflict.kept, 48),
      rejected: proof(conflict.rejected, 48),
    })),
    finAt: side.finAt,
    resetAt: side.resetAt,
  };
}

/**
 * 请求与响应按流水线顺序配对。
 * - 1xx 是中间响应，挂到紧随其后的最终响应所属请求上。
 * - 截断的响应仍与当前请求配对，并标记为 truncated；不能让后面的请求“越过”它。
 * - 时间戳早于请求的响应不可能回答该请求，标为 precedes-request 并跳过。
 * - 没有请求可配的响应标为无主：若它时间上早于所有请求则为 precedes-request，
 *   否则为 request-missing。
 *
 * timestamps 可选：{ requests: number[], responses: number[] }，用于防止时间戳交错时串配。
 */
export function pairMessages(requests, responses, timestamps = null) {
  const entries = [];
  let cursor = 0;
  const requestTime = index => timestamps?.requests?.[index] ?? null;
  const responseTime = index => timestamps?.responses?.[index] ?? null;
  for (let requestIndex = 0; requestIndex < requests.length; requestIndex += 1) {
    const request = requests[requestIndex];
    if (!request.complete) {
      entries.push({ state: 'request-incomplete', request, interim: [], response: null, detail: request.reason });
      continue;
    }
    const interim = [];
    let final = null;
    while (cursor < responses.length) {
      const response = responses[cursor];
      const requestTimestamp = requestTime(requestIndex);
      const responseTimestamp = responseTime(cursor);
      if (requestTimestamp !== null && responseTimestamp !== null
        && responseTimestamp.nanoseconds + tolerance(requestTimestamp, responseTimestamp) < requestTimestamp.nanoseconds) {
        // 观察时间（含量化误差）早于请求：只可能是半途开始前的其它请求的回执。
        response.precedesRequest = true;
        cursor += 1;
        continue;
      }
      if (response.interim) {
        interim.push(response);
        response.interimUsed = true;
        cursor += 1;
        continue;
      }
      final = response;
      response.paired = true;
      cursor += 1;
      break;
    }
    if (final) {
      entries.push({
        state: 'paired',
        request,
        interim,
        response: final,
        detail: final.complete ? null : final.reason,
        interimAmbiguous: interim.length > 1,
      });
    } else {
      entries.push({
        state: interim.length ? 'final-missing' : 'response-missing',
        request,
        interim,
        response: null,
        detail: interim.length ? '只有中间响应，最终回执缺失' : '没有可配对的最终响应',
      });
    }
  }
  for (; cursor < responses.length; cursor += 1) {
    const response = responses[cursor];
    const firstRequestTimestamp = requestTime(0);
    const responseTimestamp = responseTime(cursor);
    // 只有确实（含量化误差）早于所有请求的响应才算“先于请求”；其它无主响应是 request-missing。
    response.precedesRequest = firstRequestTimestamp !== null && responseTimestamp !== null
      && responseTimestamp.nanoseconds + tolerance(firstRequestTimestamp, responseTimestamp) < firstRequestTimestamp.nanoseconds;
  }
  return { entries };
}
