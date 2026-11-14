import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startFixture } from '../fixtures/source.mjs';
import { startService } from './service.mjs';

// 演示：只读本地演练来源，提取请求/回执关联并保存一次接收记录。
const directory = await mkdtemp(join(tmpdir(), 'capture-demo-'));
const source = await startFixture();
let service;
try {
  service = await startService({ source: source.url, directory });
  const response = await fetch(service.url + '/receive?key=demo');
  const result = await response.json();
  const value = result.value ?? result;
  console.log(JSON.stringify({
    source: source.url,
    status: response.status,
    summary: value.summary,
    ledger: value.ledger,
    fragments: value.fragments.map(fragment => ({
      kind: fragment.kind,
      state: fragment.state ?? null,
      reason: fragment.reason ?? null,
    })),
    receipt: { key: result.key, digest: result.digest },
  }, null, 2));
  if (!response.ok) process.exitCode = 1;
} finally {
  await service?.close();
  await source.close();
  await rm(directory, { recursive: true, force: true });
}
