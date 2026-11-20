//! Reconstruct self-contained payload images in memory or in a regular file,
//! without opening any device or treating manifest hashes as signature verification.
use crate::payload_plan::{Kind, Operation, Partition};
use anyhow::{Context, Result, bail, ensure};
use bzip2::{Decompress, Status};
use crc::{CRC_32_ISO_HDLC, CRC_64_XZ, Crc};
use lzma_rust2::Lzma2Reader;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

const MAX_PARTITION: u64 = 128 << 20;
const MAX_OPERATION: u64 = 8 << 20;
const MAX_DICT: u32 = 16 << 20;
const MAX_OPERATIONS: usize = 16_384;
const MAX_EXTENTS: usize = 32_768;
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
const CRC64: Crc<u64> = Crc::<u64>::new(&CRC_64_XZ);

/// Reconstruct a partition from the exact intervals of an already checked
/// manifest. Check every data-bearing operation's SHA-256, exact output byte
/// count and final partition SHA-256. `maximum` is an additional caller limit.
/// No stream may allocate from an unscreened container header.
pub fn reconstruct<R: Read + Seek>(reader: &mut R, partition: &Partition, maximum: u64) -> Result<Vec<u8>> {
    preflight(reader, partition, maximum.min(MAX_PARTITION))?;
    let mut image = zeroes(partition.size as usize)?;
    for (index, op) in partition.operations.iter().enumerate() {
        if op.kind == Kind::Zero { continue; } // Image already zeroed; overlaps were forbidden.
        let decoded = decode_operation(reader, op)
            .with_context(|| format!("reconstruct {} operation {index}", partition.name))?;
        let mut offset = 0;
        for extent in &op.targets {
            let len = (extent.end - extent.start) as usize;
            image[extent.start as usize..extent.end as usize].copy_from_slice(&decoded[offset..offset + len]);
            offset += len;
        }
    }
    let digest: [u8; 32] = Sha256::digest(&image).into();
    ensure!(digest == partition.sha256, "{} staged image SHA-256 mismatch", partition.name);
    Ok(image)
}

fn preflight(reader: &mut (impl Read + Seek), partition: &Partition, maximum: u64) -> Result<()> {
    ensure!((1..=maximum).contains(&partition.size), "{} partition is outside staging size bounds", partition.name);
    let source_size = reader.seek(SeekFrom::End(0)).context("check staging input size")?;
    ensure!((1..=MAX_OPERATIONS).contains(&partition.operations.len()), "invalid staging operation count");
    let mut coverage = Vec::new();
    for op in &partition.operations {
        let maximum = if op.kind == Kind::Zero { MAX_PARTITION } else { MAX_OPERATION };
        ensure!((1..=maximum).contains(&op.output_size), "operation output exceeds staging limit");
        let mut size = 0u64;
        for extent in &op.targets {
            ensure!(coverage.len() < MAX_EXTENTS && extent.start < extent.end && extent.end <= partition.size,
                "invalid staging target extent");
            size = size.checked_add(extent.end - extent.start).context("staging extent length overflow")?;
            coverage.push(extent.clone());
        }
        ensure!(size == op.output_size, "operation output length disagrees with target extents");
        match (&op.kind, &op.data) {
            (Kind::Zero, None) => (),
            (Kind::Zero, Some(_)) | (_, None) => bail!("operation has unexpected blob presence"),
            (kind, Some(blob)) => {
                let len = blob.range.end.checked_sub(blob.range.start).context("invalid blob range")?;
                ensure!((1..=MAX_OPERATION).contains(&len), "compressed operation exceeds staging limit");
                ensure!(blob.range.end <= source_size, "operation blob extends past staging input");
                ensure!(*kind != Kind::Replace || len == size, "raw operation length disagrees with output size");
            }
        }
    }
    coverage.sort_unstable_by_key(|range| range.start);
    let mut end = 0;
    for extent in coverage {
        ensure!(extent.start == end, "staging targets overlap or leave uncovered bytes");
        end = extent.end;
    }
    ensure!(end == partition.size, "staging targets do not cover partition");
    Ok(())
}

/// Stage at `base` in a newly created, pre-sized regular image opened for
/// reading and writing. The caller owns it exclusively and must discard it
/// after any failure; hash or I/O failures can leave partially staged bytes.
/// The descriptor alone cannot establish creation history or current zeros,
/// so ZERO extents are written explicitly, even if the image is sparse.
pub(crate) fn stage_into<R: Read + Seek>(reader: &mut R, partition: &Partition, output: &mut File, base: u64, device_size: u64) -> Result<()> {
    let metadata = output.metadata().context("inspect staging output")?;
    ensure!(metadata.is_file() && metadata.len() == device_size, "staging output must be a regular image of exactly {device_size} bytes");
    // With O_APPEND even a seeked write can extend the file. Reject before
    // touching the image; O_RDWR is also required for the final file hash.
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 { return Err(std::io::Error::last_os_error()).context("query image descriptor flags"); }
    ensure!(flags & libc::O_ACCMODE == libc::O_RDWR && flags & libc::O_APPEND == 0,
        "staging output needs a non-append read/write descriptor");
    ensure!(base.checked_add(partition.size).is_some_and(|end| end <= device_size), "partition staging interval exceeds image");
    preflight(reader, partition, device_size - base)?;

    const CHUNK: usize = 64 << 10;
    let mut buffer = vec![0; CHUNK];
    for (index, op) in partition.operations.iter().enumerate() {
        let staged = (|| -> Result<()> {
            let decoded = if op.kind == Kind::Zero { None } else { Some(decode_operation(reader, op)?) };
            let mut offset = 0;
            for extent in &op.targets {
                // Every extent is inside the checked partition interval.
                output.seek(SeekFrom::Start(base + extent.start))?;
                let len = extent.end - extent.start;
                if let Some(bytes) = &decoded {
                    let len = len as usize;
                    output.write_all(&bytes[offset..offset + len])?;
                    offset += len;
                } else {
                    let mut left = len;
                    while left != 0 {
                        let take = left.min(CHUNK as u64) as usize;
                        output.write_all(&buffer[..take])?;
                        left -= take as u64;
                    }
                }
            }
            Ok(())
        })();
        staged.with_context(|| format!("stage {} operation {index}", partition.name))?;
    }
    output.seek(SeekFrom::Start(base))?;
    let mut digest = Sha256::new();
    let mut left = partition.size;
    while left != 0 {
        let take = left.min(CHUNK as u64) as usize;
        output.read_exact(&mut buffer[..take]).context("read staged image bytes")?;
        digest.update(&buffer[..take]);
        left -= take as u64;
    }
    let digest: [u8; 32] = digest.finalize().into();
    ensure!(digest == partition.sha256, "{} staged image SHA-256 mismatch", partition.name);
    Ok(())
}

fn zeroes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).context("allocate payload staging buffer")?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn decode_operation(reader: &mut (impl Read + Seek), op: &Operation) -> Result<Vec<u8>> {
    let blob = op.data.as_ref().context("missing operation blob")?;
    let mut bytes = zeroes((blob.range.end - blob.range.start) as usize)?;
    reader.seek(SeekFrom::Start(blob.range.start))?;
    reader.read_exact(&mut bytes).context("read exact operation blob")?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    ensure!(digest == blob.sha256, "operation blob SHA-256 mismatch");
    if op.kind == Kind::Replace { return Ok(bytes); }
    let mut output = zeroes(op.output_size as usize)?;
    match op.kind {
        Kind::ReplaceXz => xz(&bytes, &mut output)?,
        Kind::ReplaceBz => bz(&bytes, &mut output)?,
        _ => bail!("unsupported compressed operation"),
    }
    Ok(output)
}

fn bz(input: &[u8], output: &mut [u8]) -> Result<()> {
    let mut decoder = Decompress::new(true); // low-memory backend (header level 1–9)
    let status = decoder.decompress(input, output).context("decode bzip2 operation")?;
    ensure!(decoder.total_out() == output.len() as u64, "bzip2 operation produced too little data");
    // A full output buffer can defer processing the stream terminator / CRC.
    if status != Status::StreamEnd {
        ensure!(status == Status::Ok, "unexpected bzip2 decoder status {status:?}");
        let mut probe = [0];
        let status = decoder.decompress(&input[decoder.total_in() as usize..], &mut probe)
            .context("finish bzip2 stream and verify checksum")?;
        ensure!(status == Status::StreamEnd && decoder.total_out() == output.len() as u64,
            "bzip2 operation did not terminate within the output bound");
    }
    ensure!(decoder.total_in() == input.len() as u64, "trailing data after bzip2 stream");
    Ok(())
}

fn le32(bytes: &[u8]) -> u32 { u32::from_le_bytes(bytes.try_into().expect("fixed four byte field")) }
fn round4(value: usize) -> Result<usize> { Ok(value.checked_add(3).context("XZ alignment overflow")? & !3) }
fn zeros(bytes: &[u8]) -> bool { bytes.iter().all(|&b| b == 0) }

fn vli(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0;
    for i in 0..9 {
        let (&b, rest) = input.split_first().context("truncated XZ variable-length field")?;
        *input = rest;
        value |= u64::from(b & 127) << (7 * i);
        if b < 128 {
            ensure!(i == 0 || b != 0, "noncanonical XZ variable-length field");
            return Ok(value);
        }
    }
    bail!("oversized XZ variable-length field")
}

/// The OTA writer emits a single XZ stream, a single block and a single
/// LZMA2 filter. Parse that narrow profile ourselves: an XZ container reader
/// would otherwise let its filter headers allocate an arbitrary dictionary.
fn xz(input: &[u8], output: &mut [u8]) -> Result<()> {
    ensure!(input.len() >= 36 && input.len() % 4 == 0 && input.starts_with(b"\xfd7zXZ\x00"), "invalid XZ stream framing");
    let flags = &input[6..8];
    let check_size = match flags { [0,0] => 0, [0,1] => 4, [0,4] => 8, [0,10] => 32, _ => bail!("unsupported XZ checksum or flags") };
    ensure!(CRC32.checksum(flags) == le32(&input[8..12]), "XZ header checksum mismatch");
    let footer_at = input.len() - 12;
    let footer = &input[footer_at..];
    ensure!(&footer[10..] == b"YZ" && &footer[8..10] == flags && CRC32.checksum(&footer[4..10]) == le32(&footer[..4]), "malformed XZ footer");
    let index_size = (u64::from(le32(&footer[4..8])) + 1) * 4;
    ensure!((8..=32).contains(&index_size), "invalid single-block XZ index size");
    let index_at = footer_at.checked_sub(index_size as usize).context("truncated XZ index")?;
    ensure!(index_at > 12, "XZ index overlaps stream header");
    let index = &input[index_at..footer_at - 4];
    ensure!(index[0] == 0 && CRC32.checksum(index) == le32(&input[footer_at-4..footer_at]), "malformed XZ index");
    let mut fields = &index[1..];
    ensure!(vli(&mut fields)? == 1, "expected a single XZ block");
    let block_unpadded = usize::try_from(vli(&mut fields)?)?;
    ensure!(vli(&mut fields)? == output.len() as u64, "XZ block's output length disagrees with manifest");
    ensure!(fields.len() < 4 && zeros(fields) && round4(block_unpadded)? == index_at - 12,
        "invalid XZ index padding or block size");

    let block_header_size = (usize::from(input[12]) + 1) * 4;
    ensure!((8..=64).contains(&block_header_size) && block_header_size < index_at - 12, "invalid XZ block header size");
    let header = &input[12..12+block_header_size];
    ensure!(CRC32.checksum(&header[..block_header_size-4]) == le32(&header[block_header_size-4..]), "XZ block header checksum mismatch");
    let block_flags = header[1];
    ensure!(block_flags & 0x3f == 0, "XZ requires one LZMA2 filter and no reserved flags");
    let mut properties = &header[2..block_header_size-4];
    let compressed = block_unpadded.checked_sub(block_header_size + check_size).context("XZ compressed block size underflow")?;
    ensure!(compressed > 0, "empty XZ compressed input");
    if block_flags & 0x40 != 0 { ensure!(vli(&mut properties)? == compressed as u64, "XZ compressed length mismatch"); }
    if block_flags & 0x80 != 0 { ensure!(vli(&mut properties)? == output.len() as u64, "XZ uncompressed length mismatch"); }
    ensure!(vli(&mut properties)? == 0x21 && vli(&mut properties)? == 1, "XZ block does not use the audited LZMA2 filter");
    let (&dict, padding) = properties.split_first().context("missing LZMA2 dictionary property")?;
    ensure!(dict <= 24 && zeros(padding), "XZ dictionary property or block header padding is invalid");
    let dictionary = (2 + u32::from(dict & 1)) << (u32::from(dict) / 2 + 11);
    ensure!(dictionary <= MAX_DICT, "XZ dictionary exceeds staging memory budget");
    let data_start = 12 + block_header_size;
    let data_end = data_start + compressed;
    let check_at = index_at - check_size;
    ensure!(data_end <= check_at && check_at - data_end < 4 && zeros(&input[data_end..check_at]), "invalid XZ block data padding");

    let mut decoder = Lzma2Reader::new(&input[data_start..data_end], dictionary, None);
    decoder.read_exact(output).context("read exact XZ operation output")?;
    ensure!(decoder.read(&mut [0])? == 0 && decoder.into_inner().is_empty(), "XZ stream overproduced or has trailing LZMA2 data");
    let check = &input[check_at..index_at];
    ensure!(match check_size {
        0 => true,
        4 => CRC32.checksum(output).to_le_bytes() == check,
        8 => CRC64.checksum(output).to_le_bytes() == check,
        32 => Sha256::digest(output).as_slice() == check,
        _ => false,
    }, "XZ block data checksum mismatch");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_plan::Blob;
    use std::io::Cursor;

    fn blob(kind: Kind, start: u64, contents: &[u8], extents: &[(u64, u64)]) -> Operation {
        Operation { kind, data: Some(Blob {range: start..start + contents.len() as u64, sha256: Sha256::digest(contents).into()}),
            targets: extents.iter().map(|&(a,b)| a..b).collect(), output_size: extents.iter().map(|&(a,b)| b - a).sum() }
    }

    #[test]
    fn scatters_within_operation_order_and_zero_fills() {
        let mut source = Cursor::new(*b"prefixcdab");
        let mut partition = Partition {name:"boot".into(), size:5, sha256:Sha256::digest(b"ab\0cd").into(), operations:vec![
            blob(Kind::Replace, 6, b"cdab", &[(3,5),(0,2)]), Operation {kind:Kind::Zero, targets:vec![2..3], output_size:1,data:None},
        ]};
        assert_eq!(reconstruct(&mut source,&partition,5).unwrap(), b"ab\0cd");
        assert!(reconstruct(&mut source,&partition,4).is_err());
        partition.sha256[0] ^= 1;
        assert!(reconstruct(&mut source,&partition,5).unwrap_err().to_string().contains("image SHA-256"));
        partition.operations[0].data.as_mut().unwrap().sha256[0] ^= 1;
        assert!(format!("{:#}", reconstruct(&mut source,&partition,5).unwrap_err()).contains("blob SHA-256"));
        partition.operations[1].targets[0] = 1..2;
        assert!(reconstruct(&mut source,&partition,5).unwrap_err().to_string().contains("overlap"));
    }

    fn file_input() -> (Cursor<&'static [u8]>, Partition) {
        (Cursor::new(b"prefixcdab"), Partition {
            name: "system".into(), size: 5, sha256: Sha256::digest(b"ab\0cd").into(),
            operations: vec![blob(Kind::Replace, 6, b"cdab", &[(3, 5), (0, 2)]),
                Operation { kind: Kind::Zero, targets: vec![2..3], output_size: 1, data: None }],
        })
    }

    fn initialized_image() -> File {
        let mut out = tempfile::tempfile().unwrap();
        out.write_all(b"????????????").unwrap();
        out
    }

    fn read_image(out: &mut File) -> Vec<u8> {
        out.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        out.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn stages_at_offset_and_overwrites_zero_extents_without_touching_neighbors() {
        let (mut input, partition) = file_input();
        let mut out = initialized_image();
        stage_into(&mut input, &partition, &mut out, 3, 12).unwrap();
        assert_eq!(read_image(&mut out), b"???ab\0cd????");
    }

    #[test]
    fn stage_refuses_corrupt_blob_and_final_digests() {
        let (mut input, mut partition) = file_input();
        let mut out = initialized_image();
        partition.operations[0].data.as_mut().unwrap().sha256[0] ^= 1;
        let error = stage_into(&mut input, &partition, &mut out, 3, 12).unwrap_err();
        assert!(format!("{error:#}").contains("blob SHA-256"));
        assert_eq!(read_image(&mut out), b"????????????");

        partition.operations[0].data.as_mut().unwrap().sha256[0] ^= 1;
        partition.sha256[0] ^= 1;
        let error = stage_into(&mut input, &partition, &mut out, 3, 12).unwrap_err();
        assert!(format!("{error:#}").contains("image SHA-256"));
    }

    #[test]
    fn stage_refuses_overflow_invalid_extent_truncated_blob_or_wrong_output_size_before_writes() {
        let (mut input, mut partition) = file_input();
        let mut out = initialized_image();
        assert!(stage_into(&mut input, &partition, &mut out, u64::MAX, 12).is_err());
        assert!(stage_into(&mut input, &partition, &mut out, 8, 12).is_err());
        assert!(stage_into(&mut input, &partition, &mut out, 0, 13).is_err());
        assert!(stage_into(&mut Cursor::new(b"prefixcda"), &partition, &mut out, 3, 12).is_err());
        partition.operations[1].targets[0] = 0..1;
        assert!(stage_into(&mut input, &partition, &mut out, 3, 12).is_err());
        assert_eq!(read_image(&mut out), b"????????????");
    }

    #[test]
    fn stage_rejects_append_read_only_and_nonregular_outputs() {
        let (mut input, partition) = file_input();
        let temp = tempfile::NamedTempFile::new().unwrap();
        temp.as_file().set_len(12).unwrap();
        let mut out = std::fs::OpenOptions::new().read(true).append(true).open(temp.path()).unwrap();
        assert!(stage_into(&mut input, &partition, &mut out, 3, 12).is_err());
        let mut out = File::open(temp.path()).unwrap();
        assert!(stage_into(&mut input, &partition, &mut out, 3, 12).is_err());
        let dir = tempfile::tempdir().unwrap();
        let mut directory = File::open(dir.path()).unwrap();
        let size = directory.metadata().unwrap().len();
        assert!(stage_into(&mut input, &partition, &mut directory, 0, size).is_err());
        assert_eq!(temp.as_file().metadata().unwrap().len(), 12);
    }

    // Single-block XZ and bzip2 streams made with Python's lzma/bz2 modules.
    const PLAIN: &[u8] = b"an OTA block with some repeating bytes; an OTA block with some repeating bytes!";
    const XZ: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e0004e00305d00309b8003f1796486abaea2ad39a81b1fb058d4452bb609547c397d941c6a1d5016470889f54e19735b870aca7618a65c00834b2031499698ba00014c4f23e9299a1fb6f37d010000000004595a";
    const BZ: &str = "425a6839314159265359184fb21100000b1f8060000008200084003aefdca0200050a0d1a341901a05554f534c23f51a1a9fa9a3861f1086aaa50fa852337b2cb3fa5d3850ba52d12e9772aaaa28ed8b260d1e0bb9229c28480c27d90880";
    fn hex(text: &str) -> Vec<u8> { text.as_bytes().chunks_exact(2).map(|d| u8::from_str_radix(std::str::from_utf8(d).unwrap(),16).unwrap()).collect() }

    #[test]
    fn exact_decoder_streams_and_trailing_data() {
        for (decoder, contents) in [(xz as fn(&[u8], &mut [u8])->Result<()>, XZ),(bz,BZ)] {
            let mut bytes = hex(contents);
            let mut out = vec![0;PLAIN.len()];
            decoder(&bytes,&mut out).unwrap();
            assert_eq!(out, PLAIN);
            assert!(decoder(&bytes,&mut out[..PLAIN.len()-1]).is_err());
            let mut too_big = vec![0;PLAIN.len()+1];
            assert!(decoder(&bytes,&mut too_big).is_err());
            assert!(decoder(&bytes[..bytes.len()-1],&mut out).is_err());
            bytes.extend([0;4]);
            assert!(decoder(&bytes,&mut out).is_err());
        }
    }

    #[test]
    fn oversized_xz_dictionary_rejected_even_with_correct_header_crc() {
        let mut bytes = hex(XZ);
        assert_eq!(&bytes[12..20], &[2,0,0x21,1,0x16,0,0,0]);
        bytes[16] = 40;
        let crc = CRC32.checksum(&bytes[12..20]).to_le_bytes();
        bytes[20..24].copy_from_slice(&crc);
        assert!(xz(&bytes,&mut vec![0;PLAIN.len()]).unwrap_err().to_string().contains("dictionary"));
    }
}
