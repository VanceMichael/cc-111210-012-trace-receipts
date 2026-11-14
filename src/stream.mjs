// 按 TCP 序列号装配单方向字节流。
//
// 规则：
// - 连续前缀按序合并；乱序到达的片段暂存，缺口补齐后再并入。
// - 重叠字节必须逐字节一致；不一致记为冲突并终止装配，不拼出看似完整的消息。
// - 恰好接在首个片段之前的片段可以向前并入；隔开缺口的更早片段只留作证据。
// - 每连接共享缓存预算；超限时终止并给出原因，绝不丢弃旧字节后继续。

import { seqDiff, seqAdd, MAX_BODY_BYTES } from './util.mjs';

export { seqDiff, seqAdd };

export const DEFAULT_SEGMENT_LIMIT = 4096;

export class ByteBudget {
  constructor(limit) {
    this.limit = limit;
    this.used = 0;
  }

  reserve(bytes) {
    if (bytes <= 0) return true;
    if (this.used + bytes > this.limit) return false;
    this.used += bytes;
    return true;
  }
}

export class ByteStream {
  constructor({ limit = MAX_BODY_BYTES, segmentLimit = DEFAULT_SEGMENT_LIMIT, direction = '', budget = null } = {}) {
    this.limit = limit;
    this.segmentLimit = segmentLimit;
    this.direction = direction;
    this.budget = budget;
    this.base = null;       // 连续前缀的起始序列号
    this.length = 0;        // 连续前缀字节数
    this.chunks = [];       // 前缀的字节来源，按序列号升序
    this.pending = [];      // 位于前缀之后、等待缺口补齐的片段
    this.beforeBase = [];   // 位于前缀之前但未接上的片段
    this.gaps = [];
    this.conflicts = [];
    this.duplicateBytes = 0;
    this.receivedBytes = 0;
    this.terminated = null; // { reason, detail, atSequence }
    this._joined = null;
  }

  get prefix() {
    if (this._joined === null) {
      this._joined = this.chunks.length ? Buffer.concat(this.chunks.map(chunk => chunk.data)) : Buffer.alloc(0);
    }
    return this._joined;
  }

  get endSequence() {
    return this.base === null ? null : seqAdd(this.base, this.length);
  }

  get pendingBytes() {
    return this.pending.reduce((sum, item) => sum + item.data.length, 0)
      + this.beforeBase.reduce((sum, item) => sum + item.data.length, 0);
  }

  terminate(reason, detail = '', atSequence = this.endSequence) {
    if (!this.terminated) this.terminated = { reason, detail, atSequence };
    return 0;
  }

  reserve(bytes) {
    if (bytes <= 0) return true;
    if (this.budget) {
      if (this.budget.reserve(bytes)) return true;
      this.terminate('cache-limit', `连接缓存达到${this.budget.limit}字节上限`);
      return false;
    }
    if (this.length + this.pendingBytes + bytes > this.limit) {
      this.terminate('cache-limit', `方向缓存达到${this.limit}字节上限`);
      return false;
    }
    return true;
  }

  /** 喂入一个 TCP 负载片段，返回并入连续前缀的新字节数。 */
  offer(segment) {
    const data = segment.data;
    if (!data || data.length === 0) return 0;
    this.receivedBytes += data.length;
    if (this.terminated) return 0;
    if (this.base === null) this.base = segment.seq;

    const relative = seqDiff(segment.seq, this.base);
    if (relative < 0) return this.offerBeforeBase(segment, relative);
    if (relative < this.length) return this.offerOverlapping(segment, relative);
    if (relative > this.length) return this.storePending(segment.seq, data, segment, 0);
    if (!this.reserve(data.length)) return 0;
    this.append(segment.seq, data, segment, 0);
    this.drain();
    return data.length;
  }

  offerBeforeBase(segment, relative) {
    const data = segment.data;
    const endRelative = relative + data.length;
    if (endRelative <= 0) {
      if (!this.reserve(data.length)) return 0;
      if (endRelative === 0) {
        this.prepend(segment.seq, data, segment, 0);
        this.prependAdjacent();
        return data.length;
      }
      if (!this.stage(this.beforeBase, { seq: segment.seq, data, offset: 0 }, segment)) return 0;
      this.recordGap(seqAdd(segment.seq, data.length), this.base, segment.packetNumber, data.subarray(Math.max(0, data.length - 48)), this.prefix.subarray(0, 48), 'before-base');
      return 0;
    }

    // 与前缀重叠：重叠区为 [base, min(segEnd, prefixEnd))。
    const overlapLength = Math.min(endRelative, this.length);
    const incomingStart = -relative;
    const existing = this.prefix.subarray(0, overlapLength);
    const incoming = data.subarray(incomingStart, incomingStart + overlapLength);
    if (overlapLength > 0 && !existing.equals(incoming)) {
      this.conflicts.push({
        atSequence: this.base,
        length: overlapLength,
        kept: existing.subarray(0, 64),
        rejected: incoming.subarray(0, 64),
        keptPackets: this.packetNumbersFor(0, overlapLength),
        rejectedPacket: segment.packetNumber,
        rejectedInterfaceId: segment.interfaceId,
        rejectedFrameOffset: segment.frameOffset,
      });
      return this.terminate('conflict', '向前重叠字节与已接收内容冲突', this.base);
    }
    this.duplicateBytes += overlapLength;
    const head = data.subarray(0, incomingStart);
    const tail = endRelative > this.length ? data.subarray(incomingStart + this.length) : Buffer.alloc(0);
    if (!this.reserve(head.length + tail.length)) return 0;
    if (head.length) {
      this.prepend(segment.seq, head, segment, 0);
      this.prependAdjacent();
    }
    if (tail.length) {
      this.append(seqAdd(this.base, this.length), tail, segment, incomingStart + this.length);
      this.drain();
    }
    return head.length + tail.length;
  }

  offerOverlapping(segment, relative) {
    const data = segment.data;
    const overlap = Math.min(data.length, this.length - relative);
    const existing = this.prefix.subarray(relative, relative + overlap);
    const incoming = data.subarray(0, overlap);
    if (!existing.equals(incoming)) {
      this.conflicts.push({
        atSequence: seqAdd(this.base, relative),
        length: overlap,
        kept: existing.subarray(0, 64),
        rejected: incoming.subarray(0, 64),
        keptPackets: this.packetNumbersFor(relative, overlap),
        rejectedPacket: segment.packetNumber,
        rejectedInterfaceId: segment.interfaceId,
        rejectedFrameOffset: segment.frameOffset,
      });
      return this.terminate('conflict', '重叠字节与已接收内容冲突', seqAdd(this.base, relative));
    }
    this.duplicateBytes += overlap;
    if (overlap === data.length) return 0;
    const rest = data.subarray(overlap);
    if (!this.reserve(rest.length)) return 0;
    this.append(seqAdd(segment.seq, overlap), rest, segment, overlap);
    this.drain();
    return rest.length;
  }

  /**
   * 把一段字节放入暂存列表（beforeBase 或 pending）：
   * - 与已有片段重叠的字节必须一致，否则记为冲突并终止；
   * - 已被覆盖的字节不再重复保留；
   * - 只保留未被覆盖的前段/后段。
   * 返回 false 表示已终止。
   */
  stage(list, piece, segment) {
    let pieces = [piece];
    for (const other of [...list]) {
      const next = [];
      for (const current of pieces) {
        // 已有片段作为基准，新片段只在其未覆盖的区间保留。
        const length = current.data.length;
        const overlapStart = Math.max(0, seqDiff(other.seq, current.seq));
        const overlapEnd = Math.min(length, seqDiff(seqAdd(other.seq, other.data.length), current.seq));
        if (overlapEnd <= overlapStart) { next.push(current); continue; }
        const otherFrom = Math.max(0, seqDiff(current.seq, other.seq));
        const kept = other.data.subarray(otherFrom, otherFrom + (overlapEnd - overlapStart));
        const incoming = current.data.subarray(overlapStart, overlapEnd);
        if (!kept.equals(incoming)) {
          this.conflicts.push({
            atSequence: seqAdd(current.seq, overlapStart),
            length: overlapEnd - overlapStart,
            kept: kept.subarray(0, 64),
            rejected: incoming.subarray(0, 64),
            keptPackets: [other.packetNumber],
            rejectedPacket: segment.packetNumber,
            rejectedInterfaceId: segment.interfaceId,
            rejectedFrameOffset: segment.frameOffset + current.offset + overlapStart,
          });
          this.terminate('conflict', '暂存片段之间重叠字节冲突', seqAdd(current.seq, overlapStart));
          return false;
        }
        this.duplicateBytes += overlapEnd - overlapStart;
        if (overlapStart > 0) {
          next.push({ seq: current.seq, data: current.data.subarray(0, overlapStart), offset: current.offset });
        }
        if (overlapEnd < length) {
          next.push({ seq: seqAdd(current.seq, overlapEnd), data: current.data.subarray(overlapEnd), offset: current.offset + overlapEnd });
        }
      }
      pieces = next;
      if (pieces.length === 0) break;
    }
    for (const current of pieces) {
      if (current.data.length === 0) continue;
      if (list.length >= this.segmentLimit) {
        this.terminate('cache-limit', `待并片段达到${this.segmentLimit}条上限`);
        return false;
      }
      if (!this.reserve(current.data.length)) return false;
      list.push({
        seq: current.seq,
        data: current.data,
        packetNumber: segment.packetNumber,
        interfaceId: segment.interfaceId,
        frameOffset: segment.frameOffset + current.offset,
        blockOffset: segment.blockOffset,
        timestamp: segment.timestamp,
        tickNanoseconds: segment.tickNanoseconds ?? 1,
      });
    }
    return true;
  }

  storePending(seq, data, segment, offset) {
    // 暂存区按序列号区间划分：只保留没有被已有片段覆盖的字节。
    if (!this.stage(this.pending, { seq, data, offset }, segment)) return 0;
    for (const item of this.pending) {
      if (seqDiff(item.seq, this.endSequence) > 0) {
        this.recordGap(this.endSequence, item.seq, item.packetNumber, this.prefix.subarray(Math.max(0, this.length - 48)), item.data.subarray(0, 48), 'ahead');
        break;
      }
    }
    return 0;
  }

  recordGap(start, end, afterPacket, proofBefore, proofAfter, kind) {
    const length = seqDiff(end, start);
    if (length <= 0) return;
    if (this.gaps.some(gap => gap.state === 'open'
      && seqDiff(gap.startSequence, start) === 0 && seqDiff(gap.endSequence, end) === 0)) return;
    this.gaps.push({
      kind,
      startSequence: start,
      endSequence: end,
      length,
      state: 'open',
      beforePacket: this.chunks.length ? this.chunks[this.chunks.length - 1].packetNumber : null,
      afterPacket,
      proofBefore,
      proofAfter,
    });
  }

  append(seq, data, segment, offset) {
    this.chunks.push({
      seq,
      data,
      packetNumber: segment.packetNumber,
      interfaceId: segment.interfaceId,
      frameOffset: segment.frameOffset + offset,
      blockOffset: segment.blockOffset,
      timestamp: segment.timestamp,
      tickNanoseconds: segment.tickNanoseconds ?? 1,
    });
    this.length += data.length;
    this._joined = null;
    this.closeGaps();
  }

  prepend(seq, data, segment, offset) {
    this.chunks.unshift({
      seq,
      data,
      packetNumber: segment.packetNumber,
      interfaceId: segment.interfaceId,
      frameOffset: segment.frameOffset + offset,
      blockOffset: segment.blockOffset,
      timestamp: segment.timestamp,
      tickNanoseconds: segment.tickNanoseconds ?? 1,
    });
    this.base = seq;
    this.length += data.length;
    this._joined = null;
  }

  prependAdjacent() {
    let moved = true;
    while (moved) {
      moved = false;
      const candidate = this.beforeBase
        .filter(item => seqDiff(seqAdd(item.seq, item.data.length), this.base) === 0)
        .sort((a, b) => seqDiff(a.seq, b.seq))[0];
      if (!candidate) break;
      this.beforeBase = this.beforeBase.filter(item => item !== candidate);
      this.prepend(candidate.seq, candidate.data, candidate, 0);
      moved = true;
    }
    this.closeGaps();
  }

  /** 把正好接上前缀末尾的暂存片段依次并入，重叠部分仍需一致。 */
  drain() {
    let moved = true;
    while (moved) {
      moved = false;
      const target = this.endSequence;
      const candidates = this.pending
        .map(item => ({ item, distance: seqDiff(item.seq, target) }))
        .filter(entry => entry.distance <= 0 && entry.distance + entry.item.data.length > 0)
        .sort((a, b) => a.distance - b.distance);
      for (const { item, distance } of candidates) {
        if (!this.pending.includes(item)) continue;
        const skip = -distance;
        if (skip > 0) {
          const existing = this.prefix.subarray(this.length - skip);
          const incoming = item.data.subarray(0, skip);
          if (existing.length !== skip || !existing.equals(incoming)) {
            this.conflicts.push({
              atSequence: seqAdd(target, -skip),
              length: Math.min(skip, 64),
              kept: existing.subarray(0, 64),
              rejected: incoming.subarray(0, 64),
              keptPackets: this.packetNumbersFor(this.length - skip, skip),
              rejectedPacket: item.packetNumber,
              rejectedInterfaceId: item.interfaceId,
              rejectedFrameOffset: item.frameOffset,
            });
            this.terminate('conflict', '暂存片段与已接收内容冲突', seqAdd(target, -skip));
            return;
          }
          this.duplicateBytes += skip;
        }
        const rest = item.data.subarray(skip);
        this.pending = this.pending.filter(other => other !== item);
        if (rest.length > 0) this.append(seqAdd(item.seq, skip), rest, item, skip);
        this.closeGaps();
        moved = true;
        break;
      }
    }
  }

  closeGaps() {
    if (this.base === null) return;
    for (const gap of this.gaps) {
      if (gap.state !== 'open') continue;
      if (seqDiff(gap.startSequence, this.base) >= 0 && seqDiff(this.endSequence, gap.endSequence) >= 0) {
        gap.state = 'filled';
        gap.filledPacket = this.chunks.length ? this.chunks[this.chunks.length - 1].packetNumber : null;
      }
    }
  }

  packetNumbersFor(index, length) {
    const start = seqAdd(this.base, index);
    return this.chunks
      .filter(chunk => seqDiff(chunk.seq, start) < length && seqDiff(seqAdd(start, length), chunk.seq) > 0)
      .map(chunk => chunk.packetNumber);
  }

  unassembledSegments() {
    const describe = item => ({
      sequenceStart: item.seq,
      sequenceEnd: seqAdd(item.seq, item.data.length),
      bytes: item.data.length,
      packetNumber: item.packetNumber,
      interfaceId: item.interfaceId,
      preview: preview(item.data),
    });
    return [
      ...this.beforeBase.map(item => ({ ...describe(item), state: 'before-prefix', reason: '与前缀之间存在缺口或起始未知' })),
      ...this.pending.map(item => ({ ...describe(item), state: 'waiting-gap', reason: '前缀之后的缺口未补齐，未并入连续前缀' })),
    ];
  }

  /** 把消息的字节区间映射回接口、包号、帧内偏移、文件偏移与 TCP 序列号。 */
  evidenceFor(start, end) {
    if (this.base === null || end <= start) return [];
    const pieces = [];
    for (const chunk of this.chunks) {
      const chunkStart = seqDiff(chunk.seq, this.base);
      const chunkEnd = chunkStart + chunk.data.length;
      const from = Math.max(start, chunkStart);
      const to = Math.min(end, chunkEnd);
      if (to <= from) continue;
      const within = from - chunkStart;
      pieces.push({
        interfaceId: chunk.interfaceId,
        packetNumber: chunk.packetNumber,
        sequenceStart: seqAdd(this.base, from),
        sequenceEnd: seqAdd(this.base, to),
        streamStart: from,
        streamEnd: to,
        frameOffsetStart: chunk.frameOffset + within,
        frameOffsetEnd: chunk.frameOffset + within + (to - from),
        fileOffsetStart: chunk.blockOffset === null ? null : chunk.blockOffset + 28 + chunk.frameOffset + within,
        fileOffsetEnd: chunk.blockOffset === null ? null : chunk.blockOffset + 28 + chunk.frameOffset + within + (to - from),
        timestamp: chunk.timestamp,
        tickNanoseconds: chunk.tickNanoseconds,
      });
    }
    return mergePieces(pieces);
  }
}

function mergePieces(pieces) {
  const merged = [];
  for (const piece of pieces) {
    const previous = merged.at(-1);
    if (previous
      && previous.packetNumber === piece.packetNumber
      && previous.interfaceId === piece.interfaceId
      && previous.frameOffsetEnd === piece.frameOffsetStart
      && previous.streamEnd === piece.streamStart) {
      previous.streamEnd = piece.streamEnd;
      previous.sequenceEnd = piece.sequenceEnd;
      previous.frameOffsetEnd = piece.frameOffsetEnd;
      previous.fileOffsetEnd = piece.fileOffsetEnd;
      continue;
    }
    merged.push({ ...piece });
  }
  return merged;
}

function preview(data) {
  return data.subarray(0, 48).toString('latin1')
    .replace(/\\/g, '\\\\').replace(/\r/g, '\\r').replace(/\n/g, '\\n');
}
