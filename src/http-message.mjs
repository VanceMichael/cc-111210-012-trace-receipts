// HTTP/1.1 消息边界解析。只根据字节和明确的长度规则切分，不做猜测。
// complete=false 的消息带截断原因和已确定字节区间，供证据留存使用。

export const MAX_HEADER_BYTES = 256 * 1024;
export const MAX_BODY_BYTES = 64 * 1024 * 1024;

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

export function findHeaderEnd(buffer, from = 0) {
  const index = buffer.indexOf('\r\n\r\n', from, 'latin1');
  return index < 0 ? -1 : index + 4;
}

/** 解析头部块（含结尾空行）。失败时抛错，调用方转为截断/无法解析证据。 */
export function parseHead(buffer, { request }) {
  const text = buffer.toString('latin1');
  if (!text.endsWith('\r\n\r\n')) throw new Error('头部未闭合');
  if (/\r(?!\n)/.test(text)) throw new Error('头部包含非法裸回车');
  const lines = text.slice(0, -4).split('\r\n');
  const startLine = lines.shift();
  if (!startLine) throw new Error('缺少起始行');
  let start;
  if (request) {
    const match = /^([^ ]+) ([^ ]+) HTTP\/(\d)\.(\d)$/.exec(startLine);
    if (!match || !TOKEN.test(match[1])) throw new Error('请求行无效');
    start = { method: match[1], target: match[2], version: `HTTP/${match[3]}.${match[4]}` };
  } else {
    const match = /^HTTP\/(\d)\.(\d) (\d{3})(?: +(.*))?$/.exec(startLine);
    if (!match) throw new Error('状态行无效');
    start = { version: `HTTP/${match[1]}.${match[2]}`, status: Number(match[3]), reason: match[4] ?? '' };
  }
  const headers = [];
  for (const line of lines) {
    if (line === '') throw new Error('头部含空行');
    if (line[0] === ' ' || line[0] === '\t') throw new Error('不支持折行头部');
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error('头部缺少冒号');
    const name = line.slice(0, colon);
    if (!TOKEN.test(name)) throw new Error('头部名称无效');
    const value = line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '');
    headers.push({ name: name.toLowerCase(), value });
  }
  return { start, headers, headerEnd: buffer.length };
}

export function headerValues(headers, name) {
  return headers.filter(header => header.name === name).map(header => header.value);
}

function framingError(head, reason, extra = {}) {
  return { complete: false, reason, head, ...extra };
}

/** 按 RFC 9112：Transfer-Encoding 与 Content-Length 同时出现时，请求必须拒绝以防走私。 */
function hasBothFramings(head) {
  return headerValues(head.headers, 'transfer-encoding').length > 0
    && headerValues(head.headers, 'content-length').length > 0;
}

/** 请求正文长度：chunked 或 Content-Length，其余按 0。 */
function requestFraming(head) {
  if (hasBothFramings(head)) return { error: 'Transfer-Encoding与Content-Length同时出现' };
  const transfer = headerValues(head.headers, 'transfer-encoding');
  const contentLength = headerValues(head.headers, 'content-length');
  if (transfer.length) {
    const codings = transfer.join(',').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
    if (codings[codings.length - 1] !== 'chunked') return { error: '传输编码不以chunked结尾，请求无法定界' };
    return { mode: 'chunked' };
  }
  if (contentLength.length) {
    const values = contentLength.join(',').split(',').map(value => value.trim());
    if (!values.every(value => /^\d+$/.test(value))) return { error: 'Content-Length不是十进制数' };
    if (new Set(values).size !== 1) return { error: 'Content-Length互相冲突' };
    const length = Number(values[0]);
    if (!Number.isSafeInteger(length)) return { error: 'Content-Length超出安全范围' };
    return length ? { mode: 'length', length } : { mode: 'none', length: 0 };
  }
  return { mode: 'none' };
}

/** 响应正文判定：状态码与请求方法优先于头部。 */
function responseFraming(head, requestMethod) {
  const status = head.start.status;
  const bodyless = requestMethod === 'HEAD' || (status >= 100 && status < 200) || status === 204 || status === 304;
  if (bodyless) return { mode: 'none', bodylessReason: requestMethod === 'HEAD' ? 'HEAD请求' : `${status}状态` };
  // RFC 9112：两者同时出现时以 Transfer-Encoding 为准；Content-Length 的歧义必须留痕。
  const ambiguous = hasBothFramings(head);
  const transfer = headerValues(head.headers, 'transfer-encoding');
  const contentLength = headerValues(head.headers, 'content-length');
  if (transfer.length) {
    const codings = transfer.join(',').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
    if (codings[codings.length - 1] !== 'chunked') {
      return { mode: 'close', note: '传输编码不以chunked结尾，按连接关闭定界', ambiguousContentLength: ambiguous };
    }
    return { mode: 'chunked', ambiguousContentLength: ambiguous };
  }
  if (contentLength.length) {
    const values = contentLength.join(',').split(',').map(value => value.trim());
    if (!values.every(value => /^\d+$/.test(value))) return { error: 'Content-Length不是十进制数' };
    if (new Set(values).size !== 1) return { error: 'Content-Length互相冲突' };
    const length = Number(values[0]);
    if (!Number.isSafeInteger(length)) return { error: 'Content-Length超出安全范围' };
    // 显式的 Content-Length: 0 是可验证的完整消息，不按关闭定界。
    return { mode: 'length', length };
  }
  return { mode: 'close' };
}


/**
 * 在 buffer[from..] 中切出下一条消息。
 * 返回 headStart/headEnd/bodyStart/bodyEnd（相对整个 buffer）以及 complete/reason。
 * bodyEnd 在截断时指向已能确定的最后字节。
 */
export function parseMessage(buffer, from, { kind, requestMethod } = {}) {
  const headerEnd = findHeaderEnd(buffer, from);
  if (headerEnd < 0) {
    return { headStart: from, headEnd: buffer.length, bodyStart: from, bodyEnd: buffer.length, complete: false, reason: 'head-incomplete', headBytes: buffer.length - from };
  }
  if (headerEnd - from > MAX_HEADER_BYTES) {
    return { headStart: from, headEnd: headerEnd, bodyStart: headerEnd, bodyEnd: headerEnd, complete: false, reason: 'header-limit' };
  }
  let head;
  try {
    head = parseHead(buffer.subarray(from, headerEnd), { request: kind === 'request' });
  } catch (error) {
    return { headStart: from, headEnd: headerEnd, bodyStart: headerEnd, bodyEnd: headerEnd, complete: false, reason: 'malformed-head', detail: error.message };
  }
  const framing = kind === 'request' ? requestFraming(head) : responseFraming(head, requestMethod);
  if (framing.error) return framingError(head, 'framing-invalid', { headStart: from, headEnd: headerEnd, bodyStart: headerEnd, bodyEnd: headerEnd, detail: framing.error });
  const bodyStart = headerEnd;
  if (framing.mode === 'none') {
    return { headStart: from, headEnd: headerEnd, bodyStart, bodyEnd: bodyStart, complete: true, head, framing };
  }
  if (framing.mode === 'length') {
    const bodyEnd = bodyStart + framing.length;
    if (bodyEnd > buffer.length) {
      return { headStart: from, headEnd: headerEnd, bodyStart, bodyEnd: buffer.length, complete: false, reason: 'body-truncated', head, framing };
    }
    return { headStart: from, headEnd: headerEnd, bodyStart, bodyEnd, complete: true, head, framing };
  }
  if (framing.mode === 'chunked') {
    return parseChunked(buffer, from, headerEnd, head, framing);
  }
  // 关闭定界：正文一直延伸到缓冲末尾；是否完整由连接关闭和终止状态决定。
  return { headStart: from, headEnd: headerEnd, bodyStart, bodyEnd: buffer.length, complete: false, reason: 'close-delimited', head, framing };
}

function parseChunked(buffer, headStart, bodyStart, head, framing = { mode: 'chunked' }) {
  let cursor = bodyStart;
  const chunks = [];
  while (true) {
    const lineEnd = buffer.indexOf('\r\n', cursor, 'latin1');
    if (lineEnd < 0 || lineEnd - cursor > 8192) {
      return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: cursor, complete: false, reason: 'chunk-incomplete', head, framing, chunks };
    }
    const match = /^([0-9a-fA-F]{1,15})(?:[ \t]*;[^\r\n]*)?$/.exec(buffer.subarray(cursor, lineEnd).toString('latin1'));
    if (!match) {
      return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: cursor, complete: false, reason: 'chunk-line-invalid', head, framing, chunks };
    }
    const size = parseInt(match[1], 16);
    const dataStart = lineEnd + 2;
    if (size === 0) {
      // 最后一块没有数据区，也没有数据后的 CRLF；后面是尾部字段区。
      let trailerCursor = dataStart;
      while (true) {
        const trailerLineEnd = buffer.indexOf('\r\n', trailerCursor, 'latin1');
        if (trailerLineEnd < 0) {
          return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: buffer.length, complete: false, reason: 'trailer-incomplete', head, framing, chunks };
        }
        if (trailerLineEnd === trailerCursor) {
          return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: trailerLineEnd + 2, complete: true, head, framing, chunks };
        }
        trailerCursor = trailerLineEnd + 2;
        if (trailerCursor - dataStart > MAX_HEADER_BYTES) {
          return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: trailerCursor, complete: false, reason: 'trailer-limit', head, framing, chunks };
        }
      }
    }
    const dataEnd = dataStart + size;
    if (dataEnd + 2 > buffer.length) {
      return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: cursor, complete: false, reason: 'chunk-incomplete', head, framing, chunks, pendingSize: size };
    }
    if (buffer[dataEnd] !== 13 || buffer[dataEnd + 1] !== 10) {
      return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: cursor, complete: false, reason: 'chunk-terminator-invalid', head, framing, chunks };
    }
    chunks.push({ start: dataStart, end: dataEnd, size });
    cursor = dataEnd + 2;
    if (cursor - bodyStart > MAX_BODY_BYTES) {
      return { headStart, headEnd: bodyStart, bodyStart, bodyEnd: cursor, complete: false, reason: 'chunk-limit', head, framing, chunks };
    }
  }
}
