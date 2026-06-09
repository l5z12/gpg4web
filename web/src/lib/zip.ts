// Minimal, dependency-free ZIP writer (STORE method, no compression).
//
// Enough to bundle a set of text files into a downloadable archive — used for
// the ".gnupg home" export. Keeping it self-contained avoids pulling a zip
// library into the bundle.

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[n] = c >>> 0
  }
  return table
})()

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

export interface ZipEntry {
  name: string
  content: string | Uint8Array
}

interface Local {
  nameBytes: Uint8Array
  data: Uint8Array
  crc: number
  offset: number
}

function dosDateTime(d: Date): { time: number; date: number } {
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (Math.floor(d.getSeconds() / 2))
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()
  return { time, date }
}

/** Build a ZIP archive (store/no-compression) from the given entries. */
export function makeZip(entries: ZipEntry[]): Blob {
  const enc = new TextEncoder()
  const chunks: Uint8Array[] = []
  const locals: Local[] = []
  let offset = 0
  const { time, date } = dosDateTime(new Date())

  for (const entry of entries) {
    const nameBytes = enc.encode(entry.name)
    const data = typeof entry.content === 'string' ? enc.encode(entry.content) : entry.content
    const crc = crc32(data)

    const header = new DataView(new ArrayBuffer(30))
    header.setUint32(0, 0x04034b50, true) // local file header signature
    header.setUint16(4, 20, true) // version needed
    header.setUint16(6, 0, true) // flags
    header.setUint16(8, 0, true) // method = store
    header.setUint16(10, time, true)
    header.setUint16(12, date, true)
    header.setUint32(14, crc, true)
    header.setUint32(18, data.length, true) // compressed size
    header.setUint32(22, data.length, true) // uncompressed size
    header.setUint16(26, nameBytes.length, true)
    header.setUint16(28, 0, true) // extra length

    const headerBytes = new Uint8Array(header.buffer)
    chunks.push(headerBytes, nameBytes, data)
    locals.push({ nameBytes, data, crc, offset })
    offset += headerBytes.length + nameBytes.length + data.length
  }

  const centralStart = offset
  for (const l of locals) {
    const cd = new DataView(new ArrayBuffer(46))
    cd.setUint32(0, 0x02014b50, true) // central dir signature
    cd.setUint16(4, 20, true) // version made by
    cd.setUint16(6, 20, true) // version needed
    cd.setUint16(8, 0, true)
    cd.setUint16(10, 0, true) // method
    cd.setUint16(12, time, true)
    cd.setUint16(14, date, true)
    cd.setUint32(16, l.crc, true)
    cd.setUint32(20, l.data.length, true)
    cd.setUint32(24, l.data.length, true)
    cd.setUint16(28, l.nameBytes.length, true)
    cd.setUint16(30, 0, true)
    cd.setUint16(32, 0, true)
    cd.setUint16(34, 0, true)
    cd.setUint16(36, 0, true)
    cd.setUint32(38, 0, true)
    cd.setUint32(42, l.offset, true)
    const cdBytes = new Uint8Array(cd.buffer)
    chunks.push(cdBytes, l.nameBytes)
    offset += cdBytes.length + l.nameBytes.length
  }

  const centralSize = offset - centralStart
  const end = new DataView(new ArrayBuffer(22))
  end.setUint32(0, 0x06054b50, true) // end of central dir
  end.setUint16(8, locals.length, true)
  end.setUint16(10, locals.length, true)
  end.setUint32(12, centralSize, true)
  end.setUint32(16, centralStart, true)
  chunks.push(new Uint8Array(end.buffer))

  return new Blob(chunks as BlobPart[], { type: 'application/zip' })
}
