import { createInterface } from 'node:readline';
import { start } from '../web/main.mjs';
const runtime = await start();
console.log('ready');
const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  if (line === 'pump') { await runtime.pump(); console.log('flushed'); }
  if (line === 'stop') { await runtime.stop(); lines.close(); console.log('stopped'); break; }
}
