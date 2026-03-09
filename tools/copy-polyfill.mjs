// Copies the webextension-polyfill minified bundle to lib/ so it can be
// listed as the first content script in manifest.json.
import { copyFileSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
mkdirSync(resolve(root, 'lib'), { recursive: true });
copyFileSync(
  resolve(root, 'node_modules/webextension-polyfill/dist/browser-polyfill.min.js'),
  resolve(root, 'lib/browser-polyfill.min.js')
);
console.log('Polyfill copied to lib/browser-polyfill.min.js');
