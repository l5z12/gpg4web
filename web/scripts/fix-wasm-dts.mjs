// wasm-pack emits invalid TypeScript in the generated .d.ts: the bzip2-rs-sys
// export symbols (e.g. `LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompress`) contain dots,
// which are illegal as bare interface property names. Quote them so `vue-tsc`
// can parse the file.
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const dts = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'wasm', 'gpg4web_core.d.ts')
const fixed = readFileSync(dts, 'utf8').replace(
  /^(\s*readonly )([A-Za-z_][\w.]*\.[\w.]*):/gm,
  '$1"$2":',
)
writeFileSync(dts, fixed)
console.log('Patched', dts)
