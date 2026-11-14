import { listen } from './http.mjs';
import { inspect, extract } from './connector.mjs';
import { ReceiptStore } from './store.mjs';

function optionsFrom(searchParams) {
  const options = {};
  const cache = searchParams.get('cacheBytes');
  if (cache !== null) {
    const value = Number(cache);
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error('cacheBytes无效');
    options.connectionCacheBytes = value;
  }
  const scene = searchParams.get('scene');
  if (scene !== null) {
    if (!/^[a-z]+$/.test(scene)) throw new Error('scene无效');
    options.trace = `/trace/${scene}.pcapng`;
  }
  return options;
}

export async function startService({ source, directory, port = 0 }) {
  const store = new ReceiptStore(directory);
  return listen(async url => {
    if (url.pathname === '/health') return { body: { state: 'ready' } };
    if (url.pathname === '/inspect') {
      const result = await inspect(source, Object.fromEntries(url.searchParams));
      return { body: result };
    }
    if (url.pathname === '/extract') {
      const result = await extract(source, optionsFrom(url.searchParams));
      return { body: result };
    }
    if (url.pathname === '/receive') {
      const key = url.searchParams.get('key') ?? 'single';
      const result = await extract(source, optionsFrom(url.searchParams));
      return { body: await store.save(key, result) };
    }
    if (url.pathname.startsWith('/receipts/')) return { body: await store.read(url.pathname.split('/').pop()) };
    return { status: 404, body: { error: '接口不存在' } };
  }, port);
}
