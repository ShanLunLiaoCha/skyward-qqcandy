//! Validate and stage raw/sparse EROFS replacement files for offline super synthesis.
use anyhow::{Context, Result, ensure};
use crc::{CRC_32_ISO_HDLC, Crc};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX: u64 = 2 << 30;
const BLOCK: u64 = 4096;
const MAGIC: [u8; 4] = [0xe2, 0xe1, 0xf5, 0xe0];
const SPARSE_CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

fn u16le(bytes: &[u8], ix: usize) -> u16 { u16::from_le_bytes(bytes[ix..ix+2].try_into().unwrap()) }
fn u32le(bytes: &[u8], ix: usize) -> u32 { u32::from_le_bytes(bytes[ix..ix+4].try_into().unwrap()) }

#[derive(Clone, Copy)]
enum Content { Raw(u64), Fill([u8; 4]), Zero }
struct Chunk { bytes: u64, content: Content }
struct Image { bytes: u64, chunks: Vec<Chunk>, checksum: u32 }

fn open_source(path: &Path) -> Result<File> {
    ensure!(std::fs::symlink_metadata(path)?.is_file(), "replacement must be a regular image: {}", path.display());
    let fd = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    ensure!(fd.metadata()?.is_file(), "replacement is no longer a regular file");
    Ok(fd)
}

pub fn inspect(path: &Path) -> Result<u64> {
    let mut fd = open_source(path)?;
    let length = fd.metadata()?.len();
    let image = plan(&mut fd, length).with_context(|| format!("inspect replacement {}", path.display()))?;
    verify_checksum(&mut fd, &image)?;
    Ok(image.bytes)
}

/// Expand a replacement into a bounded range of an already-sized, named
/// regular output file. Offsets are positional and leave the cursor alone.
/// Validate geometry before the first write. On I/O failure the caller must
/// discard the staged output; this is not a transactional write operation.
/// The caller must have exclusive control of the staging file's size.
pub(crate) fn stage_into(path: &Path, output: &mut File, base: u64, size: u64) -> Result<()> {
    let out = output.metadata()?;
    ensure!(out.is_file() && out.nlink() > 0, "staging destination must be a named regular file");
    ensure!(base.checked_add(size).is_some_and(|end| end <= out.len()), "replacement exceeds staging file bounds");
    // Linux pwrite on an O_APPEND fd appends regardless of its offset.
    // SAFETY: the borrowed file holds a valid fd for this non-mutating query.
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 { return Err(std::io::Error::last_os_error()).context("query staging destination flags"); }
    ensure!(flags & libc::O_APPEND == 0 && matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR),
        "staging destination must be writable and not append-only");
    let mut source = open_source(path)?;
    let input = source.metadata()?;
    ensure!((input.dev(), input.ino()) != (out.dev(), out.ino()), "replacement and output are the same inode");
    let image = plan(&mut source, input.len()).with_context(|| format!("inspect replacement {}", path.display()))?;
    ensure!(image.bytes == size, "replacement expands to {} bytes; expected {size}", image.bytes);
    verify_checksum(&mut source, &image)?;
    let mut at = base;
    stream(&mut source, &image, |bytes| {
        output.write_all_at(bytes, at).context("write replacement to staging image")?;
        // `stream` emits exactly image.bytes, and base + size was checked.
        at += bytes.len() as u64;
        Ok(())
    })?;
    let after = source.metadata()?;
    ensure!(after.len() == input.len() && after.mtime() == input.mtime() && after.mtime_nsec() == input.mtime_nsec()
        && after.ctime() == input.ctime() && after.ctime_nsec() == input.ctime_nsec(), "replacement changed while staging");
    ensure!(output.metadata()?.len() == out.len(), "staging destination size changed");
    Ok(())
}

fn stream(file: &mut (impl Read + Seek), image: &Image, mut emit: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut buffer = vec![0; 64 << 10];
    for chunk in &image.chunks {
        match chunk.content {
            Content::Raw(offset) => { file.seek(SeekFrom::Start(offset))?; }
            Content::Fill(word) => { for bytes in buffer.chunks_exact_mut(4) { bytes.copy_from_slice(&word); } }
            Content::Zero => buffer.fill(0),
        }
        let mut left = chunk.bytes;
        while left != 0 {
            let take = left.min(buffer.len() as u64) as usize;
            if matches!(chunk.content, Content::Raw(_)) { file.read_exact(&mut buffer[..take])?; }
            emit(&buffer[..take])?;
            left -= take as u64;
        }
    }
    Ok(())
}

fn verify_checksum(file: &mut (impl Read + Seek), image: &Image) -> Result<()> {
    if image.checksum != 0 {
        let mut digest = SPARSE_CRC.digest();
        stream(file, image, |bytes| { digest.update(bytes); Ok(()) })?;
        ensure!(digest.finalize() == image.checksum, "sparse replacement image checksum mismatch");
    }
    Ok(())
}

fn verify_erofs(file: &mut (impl Read + Seek), raw_start: u64, image_size: u64) -> Result<()> {
    file.seek(SeekFrom::Start(raw_start + 1024))?;
    let mut sb = [0u8; 128];
    file.read_exact(&mut sb)?;
    ensure!(sb[..4] == MAGIC, "replacement does not expand to EROFS");
    ensure!(sb[12] == 12, "expected 4KiB EROFS blocks");
    let blocks = u64::from(u32le(&sb, 36));
    ensure!(blocks > 0 && blocks <= image_size / BLOCK && u64::from(u32le(&sb, 40)) < blocks,
        "EROFS superblock geometry exceeds replacement image");
    Ok(())
}

fn plan(file: &mut (impl Read + Seek), length: u64) -> Result<Image> {
    ensure!((28..=MAX).contains(&length), "replacement file outside supported size");
    let mut head = [0u8; 28];
    file.read_exact(&mut head)?;
    if u32le(&head, 0) != 0xed26ff3a {
        ensure!(length % BLOCK == 0 && length >= BLOCK, "raw replacement is not a 4KiB image");
        verify_erofs(file, 0, length)?;
        return Ok(Image { bytes: length, chunks: vec![Chunk { bytes: length, content: Content::Raw(0) }], checksum: 0 });
    }
    ensure!(u16le(&head,4)==1 && u16le(&head,6)==0 && u16le(&head,8)==28 && u16le(&head,10)==12
        && u64::from(u32le(&head,12))==BLOCK, "unsupported sparse layout for replacement");
    let total = u64::from(u32le(&head,16)) * BLOCK;
    let count = u32le(&head,20);
    ensure!((BLOCK..=MAX).contains(&total) && (1..=100_000).contains(&count), "invalid sparse size or chunk count");
    let mut offset = 28u64;
    let mut expanded = 0u64;
    let mut chunks = Vec::new();
    for idx in 0..count {
        let mut chunk = [0u8; 12];
        file.read_exact(&mut chunk)?;
        let bytes = u64::from(u32le(&chunk,4)) * BLOCK;
        let size = u64::from(u32le(&chunk,8));
        let kind = u16le(&chunk,0);
        ensure!(bytes > 0 && bytes+expanded <= total && offset+size <= length, "invalid sparse chunk geometry");
        if idx == 0 { ensure!(kind == 0xcac1, "EROFS header must be carried by first RAW sparse chunk"); }
        let content = match kind {
            0xcac1 if size == bytes+12 => Content::Raw(offset+12),
            0xcac2 if size == 16 => { let mut fill = [0; 4]; file.read_exact(&mut fill)?; Content::Fill(fill) }
            0xcac3 if size == 12 => Content::Zero,
            _ => anyhow::bail!("unsupported sparse data or checksum chunk"),
        };
        if idx == 0 { verify_erofs(file, offset+12, total)?; }
        chunks.push(Chunk { bytes, content });
        expanded += bytes;
        offset += size;
        file.seek(SeekFrom::Start(offset))?;
    }
    ensure!(offset == length && expanded == total, "sparse replacement length mismatch");
    Ok(Image { bytes: total, chunks, checksum: u32le(&head, 24) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn raw() -> Vec<u8> {
        let mut bytes = vec![0; BLOCK as usize];
        bytes[1024..1028].copy_from_slice(&MAGIC);
        bytes[1036] = 12;
        bytes[1060] = 1;
        bytes
    }

    fn sparse(checksum: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(0xed26ff3au32.to_le_bytes());
        for field in [1u16, 0, 28, 12] { bytes.extend(field.to_le_bytes()); }
        for field in [4096u32, 3, 3, checksum] { bytes.extend(field.to_le_bytes()); }
        for (kind, size, payload) in [(0xcac1u16, 4108u32, raw()), (0xcac2, 16, vec![1, 2, 3, 4]), (0xcac3, 12, Vec::new())] {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(0u16.to_le_bytes());
            bytes.extend(1u32.to_le_bytes());
            bytes.extend(size.to_le_bytes());
            bytes.extend(payload);
        }
        bytes
    }

    #[test]
    fn supplied_replacement_fixtures() {
        let (Some(company), Some(preload)) = (std::env::var_os("SKYWARD_MY_COMPANY"), std::env::var_os("SKYWARD_MY_PRELOAD")) else { return };
        for (path, size) in [(Path::new(&company), 335_872), (Path::new(&preload), 2_076_672)] {
            assert_eq!(inspect(path).unwrap(), size);
            let mut out = tempfile::NamedTempFile::new().unwrap();
            out.as_file().set_len(size).unwrap();
            stage_into(path, out.as_file_mut(), 0, size).unwrap();
            assert_eq!(inspect(out.path()).unwrap(), size);
        }
    }

    #[test]
    fn validates_raw_erofs_geometry() {
        let mut bytes = raw();
        assert_eq!(plan(&mut Cursor::new(&bytes), BLOCK).unwrap().bytes, BLOCK);
        bytes[1060] = 2;
        assert!(plan(&mut Cursor::new(&bytes), BLOCK).is_err());
        assert!(plan(&mut Cursor::new(&bytes), BLOCK - 1).is_err());
    }

    #[test]
    fn validates_sparse_expanded_size_and_exact_coverage() {
        let bytes = sparse(0);
        assert_eq!(plan(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap().bytes, 3*BLOCK);
        assert!(plan(&mut Cursor::new(&bytes), bytes.len() as u64-1).is_err());
    }

    #[test]
    fn writes_fill_and_deterministic_zero_only_inside_destination() {
        let mut expected = raw();
        expected.extend([1, 2, 3, 4].repeat(BLOCK as usize / 4));
        expected.resize(3*BLOCK as usize, 0);
        let mut input = tempfile::NamedTempFile::new().unwrap();
        input.write_all(&sparse(SPARSE_CRC.checksum(&expected))).unwrap();
        let mut out = tempfile::NamedTempFile::new().unwrap();
        out.write_all(&vec![0xab; expected.len() + 28]).unwrap();
        let pos = out.stream_position().unwrap();
        stage_into(input.path(), out.as_file_mut(), 11, expected.len() as u64).unwrap();
        assert_eq!(out.stream_position().unwrap(), pos);
        let result = std::fs::read(out.path()).unwrap();
        assert_eq!(result, [&[0xab; 11][..], &expected, &[0xab; 17]].concat());
    }

    #[test]
    fn refuses_bad_geometry_checksum_and_unsafe_descriptors_before_writing() {
        let mut input = tempfile::NamedTempFile::new().unwrap();
        input.write_all(&sparse(1)).unwrap();
        let mut out = tempfile::NamedTempFile::new().unwrap();
        let before = vec![0xcd; 3*BLOCK as usize];
        out.write_all(&before).unwrap();
        assert!(stage_into(input.path(), out.as_file_mut(), 0, 3*BLOCK).is_err());
        assert!(stage_into(input.path(), out.as_file_mut(), 1, 3*BLOCK).is_err());
        assert!(stage_into(input.path(), out.as_file_mut(), u64::MAX, 3*BLOCK).is_err());
        assert!(stage_into(input.path(), out.as_file_mut(), 0, BLOCK).is_err());
        let mut anonymous = tempfile::tempfile().unwrap();
        anonymous.set_len(3*BLOCK).unwrap();
        assert!(stage_into(input.path(), &mut anonymous, 0, 3*BLOCK).is_err());
        let mut append = OpenOptions::new().append(true).open(out.path()).unwrap();
        assert!(stage_into(input.path(), &mut append, 0, 3*BLOCK).is_err());
        let mut same = OpenOptions::new().write(true).open(input.path()).unwrap();
        assert!(stage_into(input.path(), &mut same, 0, BLOCK).unwrap_err().to_string().contains("same inode"));
        assert_eq!(std::fs::read(out.path()).unwrap(), before);
    }
}
