// 只读抓包的通用工具：序列号运算、观察时间、证据摘要。
// 所有函数只处理内存中的字节，不访问网络。

import { createHash } from 'node:crypto';

export const MAX_BODY_BYTES = 64 * 1024 * 1024;

const U32 = 0x1_0000_0000;
const HALF = 0x8000_0000;

/** 有符号序列号差：跨越 2^32 回绕仍表示前后关系。 */
export function seqDiff(a, b) {
  const raw = ((a - b) % U32 + U32) % U32;
  return raw >= HALF ? raw - U32 : raw;
}

/** 无符号序列号加法（mod 2^32）。 */
export function seqAdd(seq, delta) {
  return ((seq + delta) % U32 + U32) % U32;
}

/** 把 PCAPNG 的 64 位 tick 换算成纳秒，保留 if_tsresol 的十进制/二进制语义。 */
export function resolution(ifTsresol) {
  if (ifTsresol & 0x80) {
    const power = ifTsresol & 0x7f;
    if (power > 63) throw new Error('接口时间分辨率无效');
    const denominator = 2n ** BigInt(power);
    return {
      power, base: 2,
      numerator: 1_000_000_000n,
      denominator,
      // 一个 tick 对应的纳秒数（向上取整），用于说明该接口的量化误差。
      tickNanoseconds: Math.ceil(1_000_000_000 / Number(denominator)),
    };
  }
  if (ifTsresol > 19) throw new Error('接口时间分辨率无效');
  const denominator = 10n ** BigInt(ifTsresol);
  return {
    power: ifTsresol, base: 10,
    numerator: 1_000_000_000n,
    denominator,
    tickNanoseconds: Math.ceil(1_000_000_000 / Number(denominator)),
  };
}

export function timestampToNanoseconds(high, low, res) {
  const ticks = (BigInt(high) << 32n) | BigInt(low);
  return Number((ticks * res.numerator) / res.denominator);
}

/** 纳秒整数转十进制字符串，避免浮点误差。 */
export function nanoString(nanoseconds) {
  const value = BigInt(Math.trunc(nanoseconds));
  const negative = value < 0n;
  const absolute = negative ? -value : value;
  const seconds = absolute / 1_000_000_000n;
  const fraction = String(absolute % 1_000_000_000n).padStart(9, '0');
  return `${negative ? '-' : ''}${seconds}.${fraction}`;
}

/** 只保留可审计的短字节预览：控制字符和换行都需要显式可见。 */
export function proof(buffer, max = 160) {
  if (!buffer || buffer.length === 0) return '';
  const shown = buffer.subarray(0, max)
    .toString('latin1')
    .replace(/\\/g, '\\\\')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/[\x00-\x09\x0b-\x1f\x7f]/g, ch => `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`);
  return buffer.length > max ? `${shown}…(${buffer.length}字节)` : shown;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function hexRange(start, end) {
  return `0x${start.toString(16)}-0x${end.toString(16)}`;
}
