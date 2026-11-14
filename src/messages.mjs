// 把单方向连续字节流切分成 HTTP/1.1 消息。
// 请求与响应都只按协议边界推进；每条消息保留流内字节区间，并映射回接口/包号/字节偏移。
//
// 半途开始或缺口之后的字节可能不是消息开头：此时尝试按行边界重新同步，
// 跳过的字节作为“无法关联”的片段保留，而不是把它们硬当作一条消息。

import { parseMessage } from './http-message.mjs';
import { hexRange, proof } from './util.mjs';

function closeDisposition(stream, closeInfo) {
  if (closeInfo?.kind === 'fin') return { complete: true, reason: null };
  if (closeInfo?.kind === 'rst') return { complete: false, reason: 'connection-reset' };
  if (stream.terminated) return { complete: false, reason: `stream-${stream.terminated.reason}` };
  return { complete: false, reason: 'capture-ended' };
}

export class MessageReader {
  constructor(stream, kind, closeInfo) {
    this.stream = stream;
    this.kind = kind;
    this.closeInfo = closeInfo;
    this.buffer = stream.prefix;
    this.offset = 0;
    this.index = 0;
    this.done = false;
    this.skipped = []; // 无法作为消息开头的字节区间
  }

  /** requestMethod 只用于响应侧：HEAD 响应与 1xx/204/304 不带正文。 */
  next(requestMethod) {
    if (this.done) return null;
    while (this.offset < this.buffer.length) {
      const startOffset = this.offset;
      const startsLikeMessage = this.kind === 'request'
        ? /^[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^ \r\n]+ HTTP\/1\.[01]\r\n/.test(this.buffer.subarray(startOffset, startOffset + 80).toString('latin1'))
        : /^HTTP\/1\.[01] \d{3}/.test(this.buffer.subarray(startOffset, startOffset + 16).toString('latin1'));
      if (startsLikeMessage) return this.readAt(startOffset, requestMethod);
      // 文件中间开始、缺口之后或截断头部：尝试按行边界重新同步。
      const parsed = parseMessage(this.buffer, startOffset, { kind: this.kind, requestMethod });
      const resync = this.resync(startOffset);
      if (resync !== null) {
        this.skipped.push({ start: startOffset, end: resync, reason: 'unparsable-prefix' });
        this.offset = resync;
        continue;
      }
      // 无法重同步：把剩余字节作为无法关联的片段留存。
      this.skipped.push({ start: startOffset, end: this.buffer.length, reason: parsed.reason ?? 'not-a-message-start' });
      this.done = true;
      return null;
    }
    this.done = true;
    return null;
  }

  readAt(startOffset, requestMethod) {
    const parsed = parseMessage(this.buffer, startOffset, { kind: this.kind, requestMethod });

    let complete = parsed.complete;
    let reason = parsed.reason ?? null;
    let detail = parsed.detail ?? null;
    if (!complete && reason === 'close-delimited') {
      const disposition = closeDisposition(this.stream, this.closeInfo);
      complete = disposition.complete;
      reason = disposition.reason;
    } else if (!complete && this.closeInfo?.kind === 'rst') {
      // 定长/chunked 未收满就遇到 RST：保留原截断原因，同时标明关闭方式。
      detail = detail ?? '连接被RST关闭，消息未收满';
    }

    const message = {
      index: this.index,
      kind: this.kind,
      streamStart: parsed.headStart,
      headEnd: parsed.headEnd,
      bodyStart: parsed.bodyStart,
      bodyEnd: parsed.bodyEnd,
      complete,
      reason,
      detail,
      head: parsed.head ?? null,
      framing: parsed.framing ?? null,
      chunks: parsed.chunks ?? null,
      requestMethod: this.kind === 'response' ? requestMethod ?? null : undefined,
      interim: this.kind === 'response' && parsed.head?.start?.status >= 100 && parsed.head.start.status < 200,
    };
    this.index += 1;

    if (!complete) {
      this.done = true;
      return message;
    }
    if (parsed.bodyEnd <= startOffset) {
      this.done = true;
      message.complete = false;
      message.reason = 'parser-stalled';
      return message;
    }
    this.offset = parsed.bodyEnd;
    if (this.offset >= this.buffer.length) this.done = true;
    return message;
  }

  /** 寻找下一个看起来像起始行的位置（行边界）。找不到则返回 null。 */
  resync(from) {
    let cursor = from;
    while (cursor < this.buffer.length) {
      const lineEnd = this.buffer.indexOf('\r\n', cursor, 'latin1');
      if (lineEnd < 0) return null;
      const next = lineEnd + 2;
      if (next >= this.buffer.length) return null;
      const candidate = this.buffer.subarray(next, Math.min(next + 64, this.buffer.length)).toString('latin1');
      // 起始行后必须已经有完整的 CRLF，才视为可信的重新同步点。
      if (this.kind === 'request') {
        if (/^[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^ \r\n]+ HTTP\/1\.[01]\r\n/.test(candidate)) return next;
      } else if (/^HTTP\/1\.[01] \d{3}[^\r\n]*\r\n/.test(candidate)) {
        return next;
      }
      cursor = next;
    }
    return null;
  }

  all() {
    const messages = [];
    while (!this.done) {
      const message = this.next();
      if (!message) break;
      messages.push(message);
    }
    return messages;
  }
}

/** 把消息区间映射为可追溯证据：接口、包号、包内与文件内字节偏移。 */
export function messageEvidence(stream, message) {
  if (!message) return [];
  return stream.evidenceFor(message.streamStart, message.bodyEnd).map(piece => ({
    interfaceId: piece.interfaceId,
    packetNumber: piece.packetNumber,
    fileOffset: [piece.fileOffsetStart, piece.fileOffsetEnd],
    frameOffset: [piece.frameOffsetStart, piece.frameOffsetEnd],
    sequence: [piece.sequenceStart, piece.sequenceEnd],
    streamRange: hexRange(piece.streamStart, piece.streamEnd),
    timestamp: piece.timestamp,
    timestampResolutionNanoseconds: piece.tickNanoseconds ?? 1,
  }));
}

export function summarizeMessage(message, stream) {
  if (!message) return null;
  const body = stream.prefix.subarray(message.bodyStart, message.bodyEnd);
  const head = stream.prefix.subarray(message.streamStart, message.headEnd);
  return {
    index: message.index,
    kind: message.kind,
    complete: message.complete,
    reason: message.reason,
    detail: message.detail ?? null,
    startLine: message.head?.start ?? null,
    headers: message.head?.headers ?? null,
    framing: message.framing ?? null,
    byteRange: {
      streamStart: message.streamStart,
      headEnd: message.headEnd,
      bodyStart: message.bodyStart,
      bodyEnd: message.bodyEnd,
      length: message.bodyEnd - message.streamStart,
      text: hexRange(message.streamStart, message.bodyEnd),
    },
    bodyBytes: message.bodyEnd - message.bodyStart,
    chunkPayloadBytes: message.chunks
      ? message.chunks.reduce((sum, chunk) => sum + (chunk.size ?? chunk.end - chunk.start), 0)
      : null,
    bodyPreview: proof(body, 64) || null,
    chunkCount: message.chunks ? message.chunks.length : null,
    headPreview: proof(head, 96) || null,
    evidence: messageEvidence(stream, message),
  };
}
