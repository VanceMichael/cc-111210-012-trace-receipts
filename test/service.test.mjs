import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReceiptStore } from '../src/store.mjs';
import { startService } from '../src/service.mjs';
import { startFixture } from '../fixtures/source.mjs';

test('接收记录支持同内容重复领取并拒绝覆盖', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'receipt-'));
  try {
    const store = new ReceiptStore(directory);
    assert.deepEqual(await store.save('one', { value: 3 }), await store.save('one', { value: 3 }));
    await assert.rejects(store.save('one', { value: 4 }), /冲突/);
    await assert.rejects(store.save('../escape', {}), /无效/);
    const receipt = JSON.parse(await readFile(join(directory, 'one.json'), 'utf8'));
    receipt.value.value = 8;
    await writeFile(join(directory, 'one.json'), JSON.stringify(receipt));
    await assert.rejects(store.read('one'), /校验失败/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('服务健康检查和单次查看走真实来源', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'service-'));
  const fixture = await startFixture();
  const service = await startService({ source: fixture.url, directory });
  try {
    assert.equal((await (await fetch(service.url + '/health')).json()).state, 'ready');
    const response = await fetch(service.url + '/inspect');
    assert.equal(response.status, 200, await response.text());
    assert.equal((await fetch(service.url + '/missing')).status, 404);
  } finally { await service.close(); await fixture.close(); await rm(directory, { recursive: true, force: true }); }
});

test('提取接口与场景切换走本地来源，非法场景被拒绝', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'extract-'));
  const fixture = await startFixture();
  const service = await startService({ source: fixture.url, directory });
  try {
    const baseline = await (await fetch(service.url + '/extract')).json();
    assert.equal(baseline.summary.exchanges, 2);
    const reuse = await (await fetch(service.url + '/extract?scene=reuse')).json();
    assert.equal(reuse.summary.connections, 2);
    const interleaved = await (await fetch(service.url + '/extract?scene=interleaved')).json();
    assert.equal(interleaved.summary.exchanges, 2);
    for (const connection of interleaved.connections) {
      for (const exchange of connection.exchanges) assert.equal(exchange.order.responseAfterRequest, true);
    }
    const bogus = await fetch(service.url + '/extract?scene=../etc');
    assert.equal(bogus.status, 400);
    const cache = await fetch(service.url + '/extract?cacheBytes=0');
    assert.equal(cache.status, 400);
  } finally { await service.close(); await fixture.close(); await rm(directory, { recursive: true, force: true }); }
});

test('接收记录保存关联提取结果并可校验读回', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'extract-receipt-'));
  const fixture = await startFixture();
  const service = await startService({ source: fixture.url, directory });
  try {
    const saved = await (await fetch(service.url + '/receive?key=linked')).json();
    assert.equal(saved.value.summary.exchanges, 2);
    const read = await (await fetch(service.url + '/receipts/linked')).json();
    assert.equal(read.digest, saved.digest);
    assert.deepEqual(read.value.ledger, saved.value.ledger);
    const repeat = await (await fetch(service.url + '/receive?key=linked')).json();
    assert.equal(repeat.digest, saved.digest);
  } finally { await service.close(); await fixture.close(); await rm(directory, { recursive: true, force: true }); }
});
