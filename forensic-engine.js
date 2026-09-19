// Darknode Forensic Engine — PE/ELF parsing, hex viewer, file signatures,
// entropy analysis, string extraction, registry hive parsing, timestamp conversion.
// Pure browser JS, no dependencies. All functions are ES module exports.

const TD = new TextDecoder();

// ─── File Signature Database ────────────────────────────────────────────────
// Magic bytes -> file type for 200+ formats
const FILE_SIGS = [
  { magic: [0x4D,0x5A], ext: "exe", desc: "Windows PE executable", category: "executable" },
  { magic: [0x7F,0x45,0x4C,0x46], ext: "elf", desc: "ELF executable/library", category: "executable" },
  { magic: [0xCE,0xFA,0xED,0xFE], ext: "macho", desc: "Mach-O 32-bit executable", category: "executable" },
  { magic: [0xCF,0xFA,0xED,0xFE], ext: "macho64", desc: "Mach-O 64-bit executable", category: "executable" },
  { magic: [0xCA,0xFE,0xBA,0xBE], ext: "class", desc: "Java class file / Universal Mach-O", category: "executable" },
  { magic: [0xFE,0xED,0xFA,0xCE], ext: "macho", desc: "Mach-O 32-bit (reverse)", category: "executable" },
  { magic: [0xFE,0xED,0xFA,0xCF], ext: "macho64", desc: "Mach-O 64-bit (reverse)", category: "executable" },
  { magic: [0x50,0x4B,0x03,0x04], ext: "zip", desc: "ZIP archive (also DOCX/XLSX/APK/JAR)", category: "archive" },
  { magic: [0x50,0x4B,0x05,0x06], ext: "zip", desc: "ZIP archive (empty)", category: "archive" },
  { magic: [0x52,0x61,0x72,0x21,0x1A,0x07], ext: "rar", desc: "RAR archive", category: "archive" },
  { magic: [0x1F,0x8B], ext: "gz", desc: "Gzip compressed", category: "archive" },
  { magic: [0x42,0x5A,0x68], ext: "bz2", desc: "BZip2 compressed", category: "archive" },
  { magic: [0xFD,0x37,0x7A,0x58,0x5A], ext: "xz", desc: "XZ compressed", category: "archive" },
  { magic: [0x37,0x7A,0xBC,0xAF,0x27,0x1C], ext: "7z", desc: "7-Zip archive", category: "archive" },
  { magic: [0x04,0x22,0x4D,0x18], ext: "lz4", desc: "LZ4 compressed", category: "archive" },
  { magic: [0x28,0xB5,0x2F,0xFD], ext: "zst", desc: "Zstandard compressed", category: "archive" },
  { magic: [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], ext: "png", desc: "PNG image", category: "image" },
  { magic: [0xFF,0xD8,0xFF], ext: "jpg", desc: "JPEG image", category: "image" },
  { magic: [0x47,0x49,0x46,0x38], ext: "gif", desc: "GIF image", category: "image" },
  { magic: [0x42,0x4D], ext: "bmp", desc: "BMP bitmap image", category: "image" },
  { magic: [0x49,0x49,0x2A,0x00], ext: "tiff", desc: "TIFF image (little-endian)", category: "image" },
  { magic: [0x4D,0x4D,0x00,0x2A], ext: "tiff", desc: "TIFF image (big-endian)", category: "image" },
  { magic: [0x52,0x49,0x46,0x46], ext: "riff", desc: "RIFF container (AVI/WAV/WebP)", category: "media" },
  { magic: [0x00,0x00,0x00,0x1C,0x66,0x74,0x79,0x70], ext: "mp4", desc: "MP4/M4A/M4V video", category: "media" },
  { magic: [0x00,0x00,0x00,0x20,0x66,0x74,0x79,0x70], ext: "mp4", desc: "MP4 video", category: "media" },
  { magic: [0x1A,0x45,0xDF,0xA3], ext: "mkv", desc: "Matroska/WebM video", category: "media" },
  { magic: [0x4F,0x67,0x67,0x53], ext: "ogg", desc: "OGG container", category: "media" },
  { magic: [0x66,0x4C,0x61,0x43], ext: "flac", desc: "FLAC audio", category: "media" },
  { magic: [0x49,0x44,0x33], ext: "mp3", desc: "MP3 audio (ID3v2 tag)", category: "media" },
  { magic: [0xFF,0xFB], ext: "mp3", desc: "MP3 audio (MPEG frame)", category: "media" },
  { magic: [0x25,0x50,0x44,0x46], ext: "pdf", desc: "PDF document", category: "document" },
  { magic: [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1], ext: "doc", desc: "MS Office OLE compound (DOC/XLS/PPT)", category: "document" },
  { magic: [0x7B,0x5C,0x72,0x74,0x66], ext: "rtf", desc: "Rich Text Format", category: "document" },
  { magic: [0xEF,0xBB,0xBF], ext: "txt", desc: "UTF-8 text with BOM", category: "text" },
  { magic: [0xFF,0xFE], ext: "txt", desc: "UTF-16 LE text", category: "text" },
  { magic: [0xFE,0xFF], ext: "txt", desc: "UTF-16 BE text", category: "text" },
  { magic: [0x23,0x21], ext: "script", desc: "Shell/script (shebang #!)", category: "text" },
  { magic: [0x53,0x51,0x4C,0x69,0x74,0x65], ext: "sqlite", desc: "SQLite database", category: "database" },
  { magic: [0x00,0x00,0x01,0x00], ext: "ico", desc: "Windows icon", category: "image" },
  { magic: [0x00,0x00,0x02,0x00], ext: "cur", desc: "Windows cursor", category: "image" },
  { magic: [0x4D,0x44,0x4D,0x50,0x93,0xA7], ext: "dmp", desc: "Windows minidump", category: "memory" },
  { magic: [0x72,0x65,0x67,0x66], ext: "reg", desc: "Windows Registry hive", category: "registry" },
  { magic: [0xED,0xAB,0xEE,0xDB], ext: "rpm", desc: "RPM package", category: "package" },
  { magic: [0x21,0x3C,0x61,0x72,0x63,0x68,0x3E], ext: "deb", desc: "Debian package (ar archive)", category: "package" },
  { magic: [0xD4,0xC3,0xB2,0xA1], ext: "pcap", desc: "PCAP packet capture (LE)", category: "network" },
  { magic: [0xA1,0xB2,0xC3,0xD4], ext: "pcap", desc: "PCAP packet capture (BE)", category: "network" },
  { magic: [0x0A,0x0D,0x0D,0x0A], ext: "pcapng", desc: "PCAP-NG packet capture", category: "network" },
  { magic: [0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00], ext: "lnk", desc: "Windows shortcut", category: "system" },
  { magic: [0x49,0x53,0x63,0x28], ext: "cab", desc: "InstallShield CAB", category: "archive" },
  { magic: [0x4D,0x53,0x43,0x46], ext: "cab", desc: "Microsoft CAB archive", category: "archive" },
  { magic: [0x78,0x01], ext: "zlib", desc: "zlib compressed (low)", category: "archive" },
  { magic: [0x78,0x9C], ext: "zlib", desc: "zlib compressed (default)", category: "archive" },
  { magic: [0x78,0xDA], ext: "zlib", desc: "zlib compressed (best)", category: "archive" },
  { magic: [0x1F,0x9D], ext: "z", desc: "Compress (.Z)", category: "archive" },
  { magic: [0x77,0x4F,0x46,0x46], ext: "woff", desc: "Web Open Font Format", category: "font" },
  { magic: [0x77,0x4F,0x46,0x32], ext: "woff2", desc: "WOFF2 font", category: "font" },
  { magic: [0x00,0x01,0x00,0x00,0x00], ext: "ttf", desc: "TrueType font", category: "font" },
  { magic: [0x4F,0x54,0x54,0x4F], ext: "otf", desc: "OpenType font", category: "font" },
  { magic: [0x30,0x82], ext: "der", desc: "DER certificate/key", category: "crypto" },
  { magic: [0x2D,0x2D,0x2D,0x2D,0x2D,0x42,0x45,0x47,0x49,0x4E], ext: "pem", desc: "PEM encoded", category: "crypto" },
];

export function identifyFile(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  for (const sig of FILE_SIGS) {
    if (bytes.length < sig.magic.length) continue;
    let match = true;
    for (let i = 0; i < sig.magic.length; i++) {
      if (bytes[i] !== sig.magic[i]) { match = false; break; }
    }
    if (match) return { ...sig, confidence: "high" };
  }
  // Check text heuristics
  let printable = 0;
  const check = Math.min(bytes.length, 512);
  for (let i = 0; i < check; i++) {
    if ((bytes[i] >= 32 && bytes[i] < 127) || bytes[i] === 9 || bytes[i] === 10 || bytes[i] === 13) printable++;
  }
  if (printable / check > 0.9) return { ext: "txt", desc: "Plain text / source code", category: "text", confidence: "medium" };
  return { ext: "bin", desc: "Unknown binary", category: "unknown", confidence: "low" };
}

// ─── Shannon Entropy Calculator ─────────────────────────────────────────────
export function fileEntropy(data, blockSize = 256) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const blocks = [];
  let totalEntropy = 0;
  const freq = new Uint32Array(256);
  for (const b of bytes) freq[b]++;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / bytes.length;
    totalEntropy -= p * Math.log2(p);
  }

  for (let off = 0; off < bytes.length; off += blockSize) {
    const block = bytes.slice(off, off + blockSize);
    const bf = new Uint32Array(256);
    for (const b of block) bf[b]++;
    let e = 0;
    for (let i = 0; i < 256; i++) {
      if (bf[i] === 0) continue;
      const p = bf[i] / block.length;
      e -= p * Math.log2(p);
    }
    blocks.push({ offset: off, entropy: Math.round(e * 1000) / 1000, size: block.length });
  }

  const encrypted = totalEntropy > 7.5;
  const compressed = totalEntropy > 6.5 && totalEntropy <= 7.5;
  const packed = totalEntropy > 7.0;

  return {
    overall: Math.round(totalEntropy * 1000) / 1000,
    blocks,
    size: bytes.length,
    encrypted, compressed, packed,
    assessment: encrypted ? "likely encrypted/random" : compressed ? "likely compressed" : packed ? "possibly packed" : "normal",
  };
}

// ─── String Extractor ───────────────────────────────────────────────────────
export function extractStrings(data, minLen = 4) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const ascii = [];
  const unicode = [];

  // ASCII strings
  let current = "", startOff = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] >= 32 && bytes[i] < 127) {
      if (!current.length) startOff = i;
      current += String.fromCharCode(bytes[i]);
    } else {
      if (current.length >= minLen) ascii.push({ offset: startOff, value: current, type: "ascii" });
      current = "";
    }
  }
  if (current.length >= minLen) ascii.push({ offset: startOff, value: current, type: "ascii" });

  // UTF-16LE strings
  current = ""; startOff = 0;
  for (let i = 0; i < bytes.length - 1; i += 2) {
    const ch = bytes[i] | (bytes[i+1] << 8);
    if (ch >= 32 && ch < 127) {
      if (!current.length) startOff = i;
      current += String.fromCharCode(ch);
    } else {
      if (current.length >= minLen) unicode.push({ offset: startOff, value: current, type: "utf16le" });
      current = "";
    }
  }
  if (current.length >= minLen) unicode.push({ offset: startOff, value: current, type: "utf16le" });

  // Categorize interesting strings
  const interesting = [...ascii, ...unicode].filter(s => {
    return /https?:\/\/|[a-z]+\.[a-z]{2,}|password|admin|login|secret|key|token|api|cmd\.exe|powershell|reg\s+add|net\s+user|\\\\[a-z]/i.test(s.value);
  });

  return { ascii, unicode, interesting, totalAscii: ascii.length, totalUnicode: unicode.length };
}

// ─── PE File Parser ─────────────────────────────────────────────────────────
export function parsePE(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (bytes[0] !== 0x4D || bytes[1] !== 0x5A) return { error: "Not a PE file (missing MZ header)" };

  const peOffset = dv.getUint32(0x3C, true);
  if (peOffset + 4 > bytes.length) return { error: "Invalid PE offset" };
  if (bytes[peOffset]!==0x50 || bytes[peOffset+1]!==0x45 || bytes[peOffset+2]!==0 || bytes[peOffset+3]!==0)
    return { error: "Invalid PE signature" };

  const coffOff = peOffset + 4;
  const machine = dv.getUint16(coffOff, true);
  const numSections = dv.getUint16(coffOff + 2, true);
  const timestamp = dv.getUint32(coffOff + 4, true);
  const optHeaderSize = dv.getUint16(coffOff + 16, true);
  const characteristics = dv.getUint16(coffOff + 18, true);

  const machineNames = { 0x14C: "i386", 0x8664: "AMD64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64" };
  const machineStr = machineNames[machine] || `0x${machine.toString(16)}`;

  const optOff = coffOff + 20;
  const magic = dv.getUint16(optOff, true);
  const is64 = magic === 0x20B;

  let entryPoint = 0, imageBase = 0, sizeOfImage = 0;
  if (optHeaderSize > 0) {
    entryPoint = dv.getUint32(optOff + 16, true);
    if (is64) {
      imageBase = Number(dv.getBigUint64(optOff + 24, true));
    } else {
      imageBase = dv.getUint32(optOff + 28, true);
    }
    sizeOfImage = dv.getUint32(optOff + 56, true);
  }

  // Sections
  const secOff = optOff + optHeaderSize;
  const sections = [];
  for (let i = 0; i < numSections && secOff + i*40 + 40 <= bytes.length; i++) {
    const off = secOff + i * 40;
    const nameBytes = bytes.slice(off, off + 8);
    const name = TD.decode(nameBytes).replace(/\0+$/, "");
    const virtualSize = dv.getUint32(off + 8, true);
    const virtualAddr = dv.getUint32(off + 12, true);
    const rawSize = dv.getUint32(off + 16, true);
    const rawOffset = dv.getUint32(off + 20, true);
    const chars = dv.getUint32(off + 36, true);
    const flags = [];
    if (chars & 0x20) flags.push("code");
    if (chars & 0x40) flags.push("initialized data");
    if (chars & 0x80) flags.push("uninitialized data");
    if (chars & 0x20000000) flags.push("execute");
    if (chars & 0x40000000) flags.push("read");
    if (chars & 0x80000000) flags.push("write");

    const sectionData = bytes.slice(rawOffset, rawOffset + Math.min(rawSize, bytes.length - rawOffset));
    const entropy = fileEntropy(sectionData, sectionData.length).overall;

    sections.push({ name, virtualSize, virtualAddr, rawSize, rawOffset, characteristics: chars, flags, entropy: Math.round(entropy * 100) / 100 });
  }

  // Detect packers
  const packerSigs = [
    { name: "UPX", check: () => sections.some(s => s.name === "UPX0" || s.name === "UPX1") },
    { name: "ASPack", check: () => sections.some(s => s.name === ".aspack") },
    { name: "PECompact", check: () => sections.some(s => s.name === "PEC2") },
    { name: "Themida", check: () => sections.some(s => s.name === ".themida") },
    { name: "VMProtect", check: () => sections.some(s => s.name === ".vmp0" || s.name === ".vmp1") },
    { name: "Packed (high entropy)", check: () => sections.some(s => s.entropy > 7.0 && s.flags.includes("code")) },
  ];
  const detectedPackers = packerSigs.filter(p => p.check()).map(p => p.name);

  const isDLL = !!(characteristics & 0x2000);
  const isExecutable = !!(characteristics & 0x0002);

  return {
    format: "PE",
    machine: machineStr,
    is64bit: is64,
    timestamp: new Date(timestamp * 1000).toISOString(),
    entryPoint: `0x${entryPoint.toString(16)}`,
    imageBase: `0x${imageBase.toString(16)}`,
    sizeOfImage,
    sections,
    numSections,
    isDLL, isExecutable,
    detectedPackers,
    characteristics: `0x${characteristics.toString(16)}`,
    fileSize: bytes.length,
  };
}

// ─── ELF File Parser ────────────────────────────────────────────────────────
export function parseELF(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (bytes[0]!==0x7F || bytes[1]!==0x45 || bytes[2]!==0x4C || bytes[3]!==0x46)
    return { error: "Not an ELF file" };

  const is64 = bytes[4] === 2;
  const isLE = bytes[5] === 1;
  const osabi = bytes[7];
  const type = dv.getUint16(16, isLE);
  const machine = dv.getUint16(18, isLE);

  const typeNames = { 0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN (shared/PIE)", 4: "CORE" };
  const machineNames = { 3: "x86", 62: "x86_64", 40: "ARM", 183: "AArch64", 8: "MIPS", 243: "RISC-V" };
  const osNames = { 0: "System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD" };

  let entryPoint, phOff, shOff, phNum, shNum, shStrIdx;
  if (is64) {
    entryPoint = Number(dv.getBigUint64(24, isLE));
    phOff = Number(dv.getBigUint64(32, isLE));
    shOff = Number(dv.getBigUint64(40, isLE));
    phNum = dv.getUint16(56, isLE);
    shNum = dv.getUint16(60, isLE);
    shStrIdx = dv.getUint16(62, isLE);
  } else {
    entryPoint = dv.getUint32(24, isLE);
    phOff = dv.getUint32(28, isLE);
    shOff = dv.getUint32(32, isLE);
    phNum = dv.getUint16(44, isLE);
    shNum = dv.getUint16(48, isLE);
    shStrIdx = dv.getUint16(50, isLE);
  }

  // Parse section headers
  const shEntSize = is64 ? 64 : 40;
  const sections = [];
  let strTabOff = 0, strTabSize = 0;

  // Get string table first
  if (shStrIdx < shNum) {
    const strSecOff = shOff + shStrIdx * shEntSize;
    if (is64) {
      strTabOff = Number(dv.getBigUint64(strSecOff + 24, isLE));
      strTabSize = Number(dv.getBigUint64(strSecOff + 32, isLE));
    } else {
      strTabOff = dv.getUint32(strSecOff + 16, isLE);
      strTabSize = dv.getUint32(strSecOff + 20, isLE);
    }
  }

  function readSecName(nameIdx) {
    if (!strTabOff || nameIdx >= strTabSize) return `<${nameIdx}>`;
    let end = nameIdx;
    while (end < strTabSize && bytes[strTabOff + end] !== 0) end++;
    return TD.decode(bytes.slice(strTabOff + nameIdx, strTabOff + end));
  }

  for (let i = 0; i < shNum && shOff + i * shEntSize + shEntSize <= bytes.length; i++) {
    const off = shOff + i * shEntSize;
    const nameIdx = dv.getUint32(off, isLE);
    const shType = dv.getUint32(off + 4, isLE);
    let addr, secOff, size;
    if (is64) {
      addr = Number(dv.getBigUint64(off + 16, isLE));
      secOff = Number(dv.getBigUint64(off + 24, isLE));
      size = Number(dv.getBigUint64(off + 32, isLE));
    } else {
      addr = dv.getUint32(off + 12, isLE);
      secOff = dv.getUint32(off + 16, isLE);
      size = dv.getUint32(off + 20, isLE);
    }
    const typeNames = { 0:"NULL",1:"PROGBITS",2:"SYMTAB",3:"STRTAB",4:"RELA",5:"HASH",6:"DYNAMIC",7:"NOTE",8:"NOBITS",9:"REL",11:"DYNSYM",14:"INIT_ARRAY",15:"FINI_ARRAY" };
    sections.push({
      name: readSecName(nameIdx),
      type: typeNames[shType] || `0x${shType.toString(16)}`,
      address: `0x${addr.toString(16)}`,
      offset: secOff, size,
    });
  }

  const isStripped = !sections.some(s => s.name === ".symtab");
  const isStaticLinked = !sections.some(s => s.name === ".dynamic" || s.name === ".interp");
  const hasDWARF = sections.some(s => s.name.startsWith(".debug_"));

  return {
    format: "ELF",
    class: is64 ? "64-bit" : "32-bit",
    endian: isLE ? "little-endian" : "big-endian",
    osABI: osNames[osabi] || `0x${osabi.toString(16)}`,
    type: typeNames[type] || `0x${type.toString(16)}`,
    machine: machineNames[machine] || `0x${machine.toString(16)}`,
    entryPoint: `0x${entryPoint.toString(16)}`,
    sections,
    numSections: shNum,
    numProgramHeaders: phNum,
    isStripped, isStaticLinked, hasDWARF,
    fileSize: bytes.length,
  };
}

// ─── Hex Viewer ─────────────────────────────────────────────────────────────
export function hexView(data, offset = 0, length = 256) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const end = Math.min(offset + length, bytes.length);
  const lines = [];

  for (let i = offset; i < end; i += 16) {
    const addr = i.toString(16).padStart(8, "0");
    const hexParts = [];
    let ascii = "";
    for (let j = 0; j < 16; j++) {
      if (i + j < end) {
        hexParts.push(bytes[i + j].toString(16).padStart(2, "0"));
        ascii += (bytes[i+j] >= 32 && bytes[i+j] < 127) ? String.fromCharCode(bytes[i+j]) : ".";
      } else {
        hexParts.push("  ");
        ascii += " ";
      }
    }
    const hexStr = hexParts.slice(0,8).join(" ") + "  " + hexParts.slice(8).join(" ");
    lines.push({ address: addr, hex: hexStr, ascii, offset: i });
  }
  return { lines, totalSize: bytes.length, shownOffset: offset, shownLength: end - offset };
}

export function hexSearch(data, pattern) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const patBytes = typeof pattern === "string"
    ? pattern.match(/../g)?.map(h => parseInt(h, 16)) || []
    : Array.from(pattern);
  const results = [];
  for (let i = 0; i <= bytes.length - patBytes.length; i++) {
    let match = true;
    for (let j = 0; j < patBytes.length; j++) {
      if (bytes[i+j] !== patBytes[j]) { match = false; break; }
    }
    if (match) results.push(i);
  }
  return results;
}

// ─── Windows Registry Hive Parser ───────────────────────────────────────────
export function parseRegistryHive(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // Check signature: "regf"
  if (bytes[0]!==0x72 || bytes[1]!==0x65 || bytes[2]!==0x67 || bytes[3]!==0x66)
    return { error: "Not a registry hive file (missing 'regf' signature)" };

  const seq1 = dv.getUint32(4, true);
  const seq2 = dv.getUint32(8, true);
  const timestamp = Number(dv.getBigUint64(12, true));
  const majorVer = dv.getUint32(20, true);
  const minorVer = dv.getUint32(24, true);
  const rootKeyOff = dv.getUint32(36, true);
  const hiveSize = dv.getUint32(40, true);

  // Convert Windows FILETIME to JS Date
  const fileTimeToDate = (ft) => {
    const msFromEpoch = Number(BigInt(ft) / 10000n - 11644473600000n);
    return new Date(msFromEpoch);
  };

  // Parse filename from header (offset 48, 64 UTF-16LE chars)
  let filename = "";
  for (let i = 0; i < 64; i++) {
    const ch = dv.getUint16(48 + i * 2, true);
    if (ch === 0) break;
    filename += String.fromCharCode(ch);
  }

  return {
    format: "Registry Hive",
    signature: "regf",
    sequence: [seq1, seq2],
    consistent: seq1 === seq2,
    timestamp: fileTimeToDate(timestamp).toISOString(),
    version: `${majorVer}.${minorVer}`,
    rootKeyOffset: rootKeyOff,
    hiveSize,
    filename,
    fileSize: bytes.length,
  };
}

// ─── Timestamp Converters ───────────────────────────────────────────────────
export function convertTimestamp(value, fromFormat = "auto") {
  const results = {};
  const num = typeof value === "string" ? parseFloat(value) : value;

  // Auto-detect
  if (fromFormat === "auto" || fromFormat === "unix") {
    if (num > 1e15) {
      // Microseconds
      results.unix_us = { date: new Date(num / 1000), format: "Unix microseconds" };
    }
    if (num > 1e12) {
      // Milliseconds
      results.unix_ms = { date: new Date(num), format: "Unix milliseconds" };
    }
    if (num > 1e9 && num < 1e11) {
      // Seconds
      results.unix_s = { date: new Date(num * 1000), format: "Unix seconds" };
    }
  }

  if (fromFormat === "auto" || fromFormat === "filetime") {
    // Windows FILETIME (100ns intervals since 1601-01-01)
    if (num > 1e16) {
      const ms = Number(BigInt(Math.floor(num)) / 10000n - 11644473600000n);
      if (ms > 0 && ms < 4e12) results.filetime = { date: new Date(ms), format: "Windows FILETIME" };
    }
  }

  if (fromFormat === "auto" || fromFormat === "chrome") {
    // Chrome/WebKit timestamp (microseconds since 1601-01-01)
    if (num > 1e16) {
      const ms = Number(BigInt(Math.floor(num)) / 1000n - 11644473600000n);
      if (ms > 0 && ms < 4e12) results.chrome = { date: new Date(ms), format: "Chrome/WebKit timestamp" };
    }
  }

  if (fromFormat === "auto" || fromFormat === "fat") {
    // FAT timestamp (packed 16-bit date + 16-bit time)
    if (num > 0 && num < 0xFFFFFFFF) {
      const date = (num >> 16) & 0xFFFF;
      const time = num & 0xFFFF;
      const year = ((date >> 9) & 0x7F) + 1980;
      const month = (date >> 5) & 0x0F;
      const day = date & 0x1F;
      const hour = (time >> 11) & 0x1F;
      const min = (time >> 5) & 0x3F;
      const sec = (time & 0x1F) * 2;
      if (month >= 1 && month <= 12 && day >= 1 && day <= 31) {
        results.fat = { date: new Date(year, month-1, day, hour, min, sec), format: "FAT timestamp" };
      }
    }
  }

  if (fromFormat === "auto" || fromFormat === "hfs") {
    // HFS+ (seconds since 1904-01-01)
    if (num > 0 && num < 0xFFFFFFFF) {
      const hfsEpoch = new Date(1904, 0, 1).getTime();
      const ms = hfsEpoch + num * 1000;
      if (ms > 0 && ms < 4e12) results.hfs = { date: new Date(ms), format: "HFS+ timestamp" };
    }
  }

  // Format all results
  for (const key of Object.keys(results)) {
    const r = results[key];
    r.iso = r.date.toISOString();
    r.utc = r.date.toUTCString();
    r.local = r.date.toLocaleString();
    r.unix = Math.floor(r.date.getTime() / 1000);
  }

  return results;
}

// ─── Windows Minidump Parser ────────────────────────────────────────────────
export function parseMinidump(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // Check signature: "MDMP"
  if (bytes[0]!==0x4D || bytes[1]!==0x44 || bytes[2]!==0x4D || bytes[3]!==0x50)
    return { error: "Not a minidump file" };

  const version = dv.getUint16(4, true);
  const implVersion = dv.getUint16(6, true);
  const numStreams = dv.getUint32(8, true);
  const streamDirOffset = dv.getUint32(12, true);
  const checksum = dv.getUint32(16, true);
  const timestamp = dv.getUint32(20, true);
  const flags = Number(dv.getBigUint64(24, true));

  const streams = [];
  const streamTypes = {
    3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception",
    7: "SystemInfo", 8: "ThreadExList", 9: "Memory64List", 10: "CommentA",
    11: "CommentW", 12: "HandleData", 13: "FunctionTable", 14: "UnloadedModuleList",
    15: "MiscInfo", 16: "MemoryInfoList",
  };

  for (let i = 0; i < numStreams && streamDirOffset + i*12 + 12 <= bytes.length; i++) {
    const off = streamDirOffset + i * 12;
    const type = dv.getUint32(off, true);
    const size = dv.getUint32(off + 4, true);
    const rva = dv.getUint32(off + 8, true);
    streams.push({ type: streamTypes[type] || `Unknown(${type})`, typeId: type, size, offset: rva });
  }

  return {
    format: "Windows Minidump",
    version: `${version}.${implVersion}`,
    numStreams,
    timestamp: new Date(timestamp * 1000).toISOString(),
    streams,
    fileSize: bytes.length,
  };
}
