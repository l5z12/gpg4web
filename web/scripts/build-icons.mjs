// Extract just the Lucide icons gpg4web uses (plus Nuxt UI's internal defaults)
// into a small JSON collection. This is registered at runtime via
// `addCollection`, so icons resolve locally — no calls to the Iconify API,
// which keeps the app fully offline and compatible with its strict CSP.
//
// Re-run after adding new `i-lucide-*` icons:  bun scripts/build-icons.mjs
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { getIcons } from '@iconify/utils'
import lucide from '@iconify-json/lucide/icons.json' with { type: 'json' }

// Nuxt UI's built-in default icons (chevrons, check, close, loader, …).
const nuxtUiDefaults = [
  'arrow-down', 'arrow-left', 'arrow-right', 'arrow-up', 'arrow-up-right',
  'check', 'chevron-down', 'chevron-left', 'chevron-right', 'chevron-up',
  'chevrons-left', 'chevrons-right', 'circle-alert', 'circle-check', 'circle-x',
  'copy', 'copy-check', 'ellipsis', 'eye', 'eye-off', 'file', 'folder',
  'folder-open', 'grip-vertical', 'hash', 'info', 'lightbulb', 'loader-circle',
  'menu', 'minus', 'monitor', 'moon', 'panel-left-close', 'panel-left-open',
  'plus', 'rotate-ccw', 'search', 'square', 'sun', 'terminal', 'triangle-alert',
  'upload', 'x',
]

// Icons referenced directly in gpg4web's templates.
const appIcons = [
  'badge-check', 'circle-check', 'circle-x', 'copy', 'download',
  'hard-drive-download', 'info', 'key-round', 'loader-circle', 'lock',
  'lock-open', 'menu', 'notebook-pen', 'package', 'plus', 'search', 'settings',
  'signature', 'star', 'star-off', 'trash-2', 'upload',
]

const names = [...new Set([...nuxtUiDefaults, ...appIcons])].sort()
const subset = getIcons(lucide, names)
if (!subset) throw new Error('failed to extract icons')

const missing = names.filter((n) => !(n in subset.icons) && !(subset.aliases && n in subset.aliases))
if (missing.length) console.warn('WARNING: icons not found in lucide:', missing.join(', '))

const out = fileURLToPath(new URL('../src/assets/lucide-icons.json', import.meta.url))
writeFileSync(out, JSON.stringify(subset))
console.log(`Wrote ${Object.keys(subset.icons).length} icons -> ${out}`)
