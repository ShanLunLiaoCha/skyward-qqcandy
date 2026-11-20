//! Android legacy LZ4 framing (8 MiB independent raw LZ4 blocks).
use anyhow::{Context, Result, ensure};

const MAGIC: [u8; 4] = [2, 0x21, 0x4c, 0x18];
const BLOCK: usize = 8 * 1024 * 1024;
const MAX_RAW: usize = 256 * 1024 * 1024;
const MAX_COMPRESSED: usize = BLOCK + BLOCK / 255 + 16;

fn length(input: &mut &[u8], head: usize) -> Result<usize> {
    let mut len = head;
    if head == 15 {
        loop {
            let (&extra, rest) = input.split_first().context("truncated LZ4 length")?;
            *input = rest;
            len += usize::from(extra);
            ensure!(len <= BLOCK, "oversized LZ4 sequence");
            if extra != 255 { break; }
        }
    }
    Ok(len)
}

pub(super) fn decode(mut input: &[u8]) -> Result<Vec<u8>> {
    ensure!(input.starts_with(&MAGIC), "stock ramdisk is not legacy LZ4");
    input = &input[4..];
    let mut out = Vec::new();
    while !input.is_empty() {
        let (size_bytes, rest) = input.split_at_checked(4).context("truncated legacy LZ4 frame")?;
        let size = u32::from_le_bytes(size_bytes.try_into()?) as usize;
        ensure!((1..=MAX_COMPRESSED).contains(&size), "invalid compressed LZ4 block length");
        let (mut block, rest) = rest.split_at_checked(size).context("truncated compressed block")?;
        input = rest;
        let base = out.len();
        loop {
            let (&token, rest) = block.split_first().context("missing LZ4 final literal sequence")?;
            block = rest;
            let literals = length(&mut block, usize::from(token >> 4))?;
            let (bytes, rest) = block.split_at_checked(literals).context("truncated LZ4 literals")?;
            ensure!(out.len() + literals <= MAX_RAW && out.len() - base + literals <= BLOCK, "ramdisk exceeds decompression limit");
            out.extend_from_slice(bytes);
            block = rest;
            if block.is_empty() { break; }
            let (offset, rest) = block.split_at_checked(2).context("truncated LZ4 offset")?;
            let offset = u16::from_le_bytes(offset.try_into()?) as usize;
            ensure!(offset != 0 && offset <= out.len() - base, "invalid LZ4 offset");
            block = rest;
            let len = length(&mut block, usize::from(token & 15))? + 4;
            ensure!(out.len() + len <= MAX_RAW && out.len() - base + len <= BLOCK, "ramdisk exceeds decompression limit");
            let start = out.len() - offset;
            if offset == 1 {
                out.resize(out.len() + len, out[start]);
            } else {
                let end = out.len() + len;
                while out.len() < end {
                    let n = (end - out.len()).min(out.len() - start);
                    out.extend_from_within(start..start+n);
                }
            }
        }
        ensure!(out.len() > base && (input.is_empty() || out.len() - base == BLOCK), "short non-final legacy LZ4 block");
    }
    ensure!(!out.is_empty(), "empty legacy LZ4 frame");
    Ok(out)
}

fn extra(length: usize, out: &mut Vec<u8>) {
    if length >= 15 {
        let remaining = length - 15;
        out.resize(out.len() + remaining / 255, 255);
        out.push((remaining % 255) as u8);
    }
}

fn sequence(literals: &[u8], match_: Option<(usize, usize)>, out: &mut Vec<u8>) {
    let match_len = match_.map_or(0, |(_, len)| len - 4);
    out.push(((literals.len().min(15) as u8) << 4) | match_len.min(15) as u8);
    extra(literals.len(), out);
    out.extend_from_slice(literals);
    if let Some((offset, _)) = match_ {
        out.extend_from_slice(&(offset as u16).to_le_bytes());
        extra(match_len, out);
    }
}

const HASH_BITS: usize = 16;
const WINDOW: usize = 65_536;
const EMPTY: usize = usize::MAX;

struct MatchFinder {
    heads: Box<[usize]>,
    chain: Box<[usize]>,
}

impl MatchFinder {
    fn new() -> Self {
        Self { heads: vec![EMPTY; 1 << HASH_BITS].into_boxed_slice(), chain: vec![EMPTY; WINDOW].into_boxed_slice() }
    }

    fn insert(&mut self, input: &[u8], at: usize) -> usize {
        let word = u32::from_le_bytes(input[at..at+4].try_into().expect("four bytes"));
        let hash = (word.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize;
        let previous = self.heads[hash];
        self.heads[hash] = at;
        self.chain[at % WINDOW] = previous;
        previous
    }

    fn find(&self, input: &[u8], at: usize, mut candidate: usize, limit: usize) -> (usize, usize) {
        let mut best = (0, 3);
        // Bounded deep chain search with lazy matching; no input-dependent
        // unbounded search. Check the best end byte before extending.
        for _ in 0..96 {
            if candidate == EMPTY || at - candidate >= WINDOW || at + best.1 >= limit { break; }
            if input[candidate + best.1] == input[at + best.1] && input[candidate..candidate+4] == input[at..at+4] {
                let mut len = 4;
                while at + len + 8 <= limit && input[candidate+len..candidate+len+8] == input[at+len..at+len+8] { len += 8; }
                while at + len < limit && input[candidate+len] == input[at+len] { len += 1; }
                if len > best.1 { best = (at - candidate, len); }
                if len >= 1024 { break; }
            }
            candidate = self.chain[candidate % WINDOW];
        }
        best
    }
}

pub(super) fn encode(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    ensure!(!input.is_empty() && input.len() <= MAX_RAW, "invalid unpacked ramdisk size");
    let mut output = MAGIC.to_vec();
    let mut finder = MatchFinder::new();
    for chunk in input.chunks(BLOCK) {
        finder.heads.fill(EMPTY);
        let mut encoded = Vec::new();
        let (mut at, mut anchor) = (0, 0);
        while at + 12 <= chunk.len() {
            let head = finder.insert(chunk, at);
            let mut next_insert = at + 1;
            let chosen = finder.find(chunk, at, head, chunk.len()-5);
            if chosen.1 < 4 { at += 1; continue; }
            // Probe the next position without registering it a second time.
            if at + 13 <= chunk.len() && chosen.1 < 1024 {
                let word = u32::from_le_bytes(chunk[at+1..at+5].try_into()?);
                let hash = (word.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize;
                if finder.find(chunk, at+1, finder.heads[hash], chunk.len()-5).1 > chosen.1 + 1 {
                    at += 1;
                    continue;
                }
            }
            sequence(&chunk[anchor..at], Some(chosen), &mut encoded);
            at += chosen.1;
            while next_insert < at && next_insert + 12 <= chunk.len() {
                finder.insert(chunk, next_insert);
                next_insert += 1;
            }
            anchor = at;
        }
        sequence(&chunk[anchor..], None, &mut encoded);
        ensure!(output.len() + 4 + encoded.len() <= limit, "compressed ramdisk does not fit the target image");
        output.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}

#[cfg(feature = "lz4-sys")]
pub(super) fn encode_hc(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    ensure!(!input.is_empty() && input.len() <= MAX_RAW, "invalid unpacked ramdisk size");
    let mut output = MAGIC.to_vec();
    let mut block = vec![0u8; MAX_COMPRESSED];
    for chunk in input.chunks(BLOCK) {
        // The raw block and exclusive output buffer are valid for the entire
        // call; lengths are bounded by the legacy 8 MiB framing constants.
        let size = unsafe { lz4_sys::LZ4_compress_HC(chunk.as_ptr().cast(), block.as_mut_ptr().cast(),
            chunk.len() as i32, block.len() as i32, 12) };
        ensure!(size > 0 && (size as usize) <= block.len(), "LZ4 HC compression failed");
        ensure!(output.len() + 4 + size as usize <= limit, "compressed ramdisk does not fit the target image");
        output.extend_from_slice(&(size as u32).to_le_bytes());
        output.extend_from_slice(&block[..size as usize]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_independent_blocks() {
        let input: Vec<_> = (0..BLOCK + 3000).map(|i| (i % 200) as u8).collect();
        let encoded = encode(&input, input.len()).unwrap();
        assert_eq!(decode(&encoded).unwrap(), input);
        assert!(encode(&input, 32).is_err());
    }
    #[test]
    fn malformed_framing_and_offsets_refused() {
        assert!(decode(&MAGIC).is_err());
        assert!(decode(&[2, 0x21, 0x4c, 0x18, 4,0,0,0, 0, 1, 0, 0]).is_err());
    }
}
