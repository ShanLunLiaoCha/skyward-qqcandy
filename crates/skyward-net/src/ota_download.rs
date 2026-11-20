//! Download a preset OTA of known HTTP length to a new local file.
//!
//! There is no catalog digest. HTTPS protects the transfer to the caller's
//! approved authority; neither TLS nor length checks verify an OTA signature.
//! Each attempt starts at byte zero and never appends to an earlier attempt.

use crate::download::{NoRoom, Progress, Refused};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use ureq::http::{HeaderMap, HeaderName, Uri, header};

const CHUNK: usize = 1 << 20;
/// Match the Recovery payload planner's upper bound; also bounds arithmetic
/// and any allocation implied by an untrusted HTTP header.
const MAX_BYTES: u64 = 128 << 30;

/// Download the entire preset `url` to a fresh `path`. The caller must have
/// approved the HTTPS authority and must provide an agent with normal TLS
/// certificate verification enabled. Redirects are not followed. A response
/// must declare the complete length and start at zero. A capped 206 is
/// continued with contiguous If-Range requests only while the same strong
/// ETag and total length hold. A stopped or failed attempt leaves no
/// resumable file.
/// A complete file is synced before publishing, without replacing a file
/// already at `path`.
///
/// Errors may contain [`NoRoom`], [`Refused`], or [`crate::Stopped`], like an
/// ordinary download. There is no `Damaged` digest verdict for this path.
pub fn fetch(agent: &ureq::Agent, url: &str, path: &Path, stop: &AtomicBool, progress: &mut dyn FnMut(Progress)) -> Result<()> {
    let uri: Uri = url.parse().context("invalid preset OTA URL")?;
    ensure!(uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|authority| !authority.as_str().contains('@')),
        "preset OTA URL must use an approved HTTPS authority without user information");
    fetch_from(agent, url, path, stop, progress)
}

fn fetch_from(agent: &ureq::Agent, url: &str, path: &Path, stop: &AtomicBool, progress: &mut dyn FnMut(Progress)) -> Result<()> {
    check_stop(stop)?;
    ensure!(path.file_name().is_some(), "the OTA destination needs a file name");
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    reject_existing(path)?;
    let mut response = request(agent, url, "bytes=0-", None, stop)?;
    let mut segment = response_segment(response.status().as_u16(), response.headers())?;
    ensure!(segment.start == 0, "the initial OTA response must start at byte zero");
    let total = segment.total;
    let validator = if segment.end < total {
        Some(strong_etag(response.headers())?.to_owned())
    } else { None };
    store_with(total, parent, path, stop, |file| {
        progress(Progress::Downloading { done: 0, total });
        for _ in 0..MAX_SEGMENTS {
            copy_segment(&mut response.body_mut().with_config().limit(segment.len() + 1).reader(),
                file, segment, stop, progress)?;
            if segment.end == total { return Ok(()); }
            let next = segment.end;
            let validator = validator.as_deref().context("missing strong OTA validator")?;
            response = request(agent, url, &format!("bytes={next}-{}", total - 1), Some(validator), stop)?;
            ensure!(response.status().as_u16() != 200, "server changed the OTA representation during download");
            segment = response_segment(response.status().as_u16(), response.headers())?;
            ensure!(segment.start == next && segment.total == total && strong_etag(response.headers())? == validator,
                "OTA range was not contiguous or the server changed the representation");
        }
        bail!("server split the OTA into too many ranges")
    })
}

const MAX_SEGMENTS: usize = 32_768;

fn request(agent: &ureq::Agent, url: &str, range: &str, validator: Option<&str>, stop: &AtomicBool)
    -> Result<ureq::http::Response<ureq::Body>> {
    check_stop(stop)?;
    let mut request = agent.get(url).header(header::RANGE, range).header(header::ACCEPT_ENCODING, "identity");
    if let Some(etag) = validator { request = request.header(header::IF_RANGE, etag); }
    let response = request.config().max_redirects(0).http_status_as_error(false).build().call();
    check_stop(stop)?;
    response.context("read preset OTA response")
}

fn check_stop(stop: &AtomicBool) -> Result<()> {
    if stop.load(Ordering::Relaxed) { bail!(crate::Stopped); }
    Ok(())
}

fn reject_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("inspect {}", path.display())),
        Ok(_) => bail!("OTA destination already exists: {}", path.display()),
    }
}

/// Reject duplicate header fields as well as merged lists (the relevant
/// fields must each contain exactly one value). Do not infer a total from the
/// HTTP library's decoded body, which may use a different framing mode.
fn single_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>> {
    let values = headers.get_all(&name);
    let mut iter = values.iter();
    let Some(value) = iter.next() else { return Ok(None); };
    ensure!(iter.next().is_none(), "duplicate OTA response header {name}");
    Ok(Some(value.to_str().with_context(|| format!("invalid OTA response header {name}"))?))
}

fn decimal(text: &str) -> Result<u64> {
    ensure!(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()), "invalid decimal OTA response length or range");
    text.parse().context("OTA response length or range overflows")
}

#[derive(Debug, Clone, Copy)]
struct Segment { start: u64, end: u64, total: u64 }

impl Segment {
    fn len(self) -> u64 { self.end - self.start }
}

fn strong_etag(headers: &HeaderMap) -> Result<&str> {
    let value = single_header(headers, header::ETAG)?.context("capped OTA response needs a strong ETag")?;
    let bytes = value.as_bytes();
    ensure!(bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'
        && bytes[1..bytes.len() - 1].iter().all(|&c| c == b'!' || (0x23..=0x7e).contains(&c)),
        "capped OTA response needs a valid strong ETag");
    Ok(value)
}

fn response_segment(status: u16, headers: &HeaderMap) -> Result<Segment> {
    if !matches!(status, 200 | 206) { bail!(Refused(status)); }
    ensure!(!headers.contains_key(header::TRANSFER_ENCODING), "OTA response must use Content-Length framing");
    ensure!(single_header(headers, header::CONTENT_ENCODING)?.is_none_or(|v| v.eq_ignore_ascii_case("identity")),
        "OTA response must not encode the byte representation");
    let length = decimal(single_header(headers, header::CONTENT_LENGTH)?.context("OTA response has no Content-Length")?)?;
    ensure!((1..=MAX_BYTES).contains(&length), "OTA response length outside supported limits");
    let range = single_header(headers, header::CONTENT_RANGE)?;
    if status == 200 {
        ensure!(range.is_none(), "unexpected Content-Range on a full OTA response");
        return Ok(Segment { start: 0, end: length, total: length });
    }
    let fields = range.and_then(|value| value.strip_prefix("bytes ")).context("invalid or missing OTA Content-Range")?;
    let (bounds, total) = fields.split_once('/').context("OTA Content-Range has no complete length")?;
    let (start, end) = bounds.split_once('-').context("OTA Content-Range has no end offset")?;
    let (start, end, total) = (decimal(start)?, decimal(end)?, decimal(total)?);
    ensure!(start <= end && end < total && total <= MAX_BYTES && end - start + 1 == length,
        "OTA Content-Range is invalid or disagrees with Content-Length");
    Ok(Segment { start, end: end + 1, total })
}

/// Use a new, owner-only directory on the destination filesystem. Temporary
/// names are not reused and the data file is opened with exclusive creation.
/// Cleanup never follows a directory tree or unlinks the published name.
struct Staged(PathBuf, File);

impl Staged {
    fn new(parent: &Path) -> Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..128 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = parent.join(format!(".skyward-ota-{}-{n}", std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let fd = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                        .open(&dir).inspect_err(|_| { let _ = fs::remove_dir(&dir); })
                        .context("pin private OTA directory")?;
                    let meta = fd.metadata().inspect_err(|_| { let _ = fs::remove_dir(&dir); })?;
                    // SAFETY: geteuid takes no arguments and has no memory side effects.
                    let uid = unsafe { libc::geteuid() };
                    if meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
                        let _ = fs::remove_dir(&dir);
                        bail!("the destination did not create a private owner-only staging directory");
                    }
                    return Ok(Self(dir, fd));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).context("create private OTA download directory"),
            }
        }
        bail!("could not reserve a private OTA download directory")
    }

    #[cfg(test)]
    fn file(&self) -> PathBuf { self.0.join("download") }

    fn create_file(&self) -> io::Result<File> {
        // SAFETY: the pinned directory and NUL-terminated basename outlive
        // the call. The returned, newly owned descriptor is closed by File.
        let fd = unsafe { libc::openat(self.1.as_raw_fd(), c"download".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600 as libc::mode_t) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn publish(&self, parent: &File, name: &CString) -> io::Result<()> {
        // SAFETY: two live directory descriptors and NUL-terminated
        // basenames. linkat fails if the destination entry already exists.
        let status = unsafe { libc::linkat(self.1.as_raw_fd(), c"download".as_ptr(),
            parent.as_raw_fd(), name.as_ptr(), 0) };
        if status < 0 { return Err(io::Error::last_os_error()); }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // SAFETY: the staging directory is held open; this never traverses
        // a directory tree or unlinks the published name.
        unsafe { libc::unlinkat(self.1.as_raw_fd(), c"download".as_ptr(), 0); }
        let _ = fs::remove_dir(&self.0);
    }
}

#[cfg(test)]
fn store(body: &mut impl Read, total: u64, parent: &Path, path: &Path, stop: &AtomicBool, progress: &mut dyn FnMut(Progress)) -> Result<()> {
    store_with(total, parent, path, stop, |file| stream(body, file, total, stop, progress))
}

fn store_with(total: u64, parent: &Path, path: &Path, stop: &AtomicBool, transfer: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    check_stop(stop)?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    reject_existing(path)?;
    let parent_fd = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent).context("open real OTA destination directory without following a symlink")?;
    let room = skyward_block::mount::space(parent).context("read destination free space")?.available;
    if total > room { bail!(NoRoom { needed: total, free: room }); }
    let name = CString::new(path.file_name().context("OTA destination needs a file name")?.as_bytes())?;
    let staged = Staged::new(parent)?;
    let mut file = staged.create_file().context("create private OTA download file")?;
    transfer(&mut file)?;
    ensure!(file.metadata()?.len() == total, "download does not have the declared OTA length");
    file.sync_all().context("sync completed OTA download")?;
    let pinned = parent_fd.metadata()?;
    let visible = fs::metadata(parent)?;
    ensure!((pinned.dev(), pinned.ino()) == (visible.dev(), visible.ino()),
        "OTA destination directory changed while downloading");
    check_stop(stop)?;
    // Never fall back to a replacing rename. Filesystems without support for
    // atomic no-clobber publication fail closed.
    staged.publish(&parent_fd, &name)
        .with_context(|| format!("publish completed OTA at {} without replacing an existing file", path.display()))?;
    parent_fd.sync_all().context("sync OTA destination directory after publication")?;
    Ok(())
}

#[cfg(test)]
fn stream(body: &mut impl Read, out: &mut impl Write, total: u64, stop: &AtomicBool, progress: &mut dyn FnMut(Progress)) -> Result<()> {
    progress(Progress::Downloading { done: 0, total });
    copy_segment(body, out, Segment { start: 0, end: total, total }, stop, progress)
}

fn copy_segment(body: &mut impl Read, out: &mut impl Write, segment: Segment, stop: &AtomicBool, progress: &mut dyn FnMut(Progress)) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = segment.start;
    while done < segment.end {
        check_stop(stop)?;
        let want = (segment.end - done).min(CHUNK as u64) as usize;
        let n = body.read(&mut buf[..want]);
        check_stop(stop)?;
        let n = match n {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other.context("read OTA response body")?,
        };
        ensure!(n != 0, "OTA response ended at byte {done}; expected through {}", segment.end - 1);
        out.write_all(&buf[..n]).context("write OTA download")?;
        done += n as u64;
        progress(Progress::Downloading { done, total: segment.total });
    }
    check_stop(stop)?;
    ensure!(body.read(&mut [0]).context("finish OTA response body")? == 0,
        "OTA response exceeds Content-Length");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Cursor};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn headers(length: &str, range: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, length.parse().unwrap());
        if let Some(range) = range { headers.insert(header::CONTENT_RANGE, range.parse().unwrap()); }
        headers
    }

    #[test]
    fn only_well_framed_unencoded_200_or_206_is_accepted() {
        assert_eq!(response_segment(200, &headers("12", None)).unwrap().total, 12);
        assert_eq!(response_segment(206, &headers("12", Some("bytes 0-11/12"))).unwrap().end, 12);
        let capped = response_segment(206, &headers("4", Some("bytes 0-3/12"))).unwrap();
        assert_eq!((capped.start, capped.end, capped.total), (0, 4, 12));
        assert!(strong_etag(&headers("4", Some("bytes 0-3/12"))).is_err());
        for (status, len, range) in [
            (200, "12", Some("bytes 0-11/12")), (206, "12", None),
            (206, "11", Some("bytes 1-12/12")), (206, "11", Some("bytes 11-1/12")),
            (206, "12", Some("bytes 0-11/*")), (206, "12", Some("bytes 0-10/12")),
            (206, "12", Some("bytes 0-11/12, bytes 0-11/12")),
            (206, "12", Some("bytes 0-18446744073709551616/12")),
            (200, "0", None), (200, "+12", None), (200, "12, 12", None),
            (200, "18446744073709551615", None), (200, "18446744073709551616", None),
        ] {
            assert!(response_segment(status, &headers(len, range)).is_err(), "{status}: {len} {range:?}");
        }
        assert!(response_segment(200, &HeaderMap::new()).is_err());
        assert_eq!(response_segment(302, &HeaderMap::new()).unwrap_err().downcast_ref::<Refused>(), Some(&Refused(302)));
        let mut h = headers("12", Some("bytes 0-11/12"));
        h.append(header::CONTENT_RANGE, "bytes 0-11/12".parse().unwrap());
        assert!(response_segment(206, &h).is_err());
        let mut h = headers("12", None);
        h.append(header::CONTENT_LENGTH, "12".parse().unwrap());
        assert!(response_segment(200, &h).is_err());
        let mut h = headers("12", None);
        h.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(response_segment(200, &h).is_err());
        h.remove(header::CONTENT_ENCODING);
        h.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        assert!(response_segment(200, &h).is_err());
    }

    #[test]
    fn streams_exact_length_and_reports_progress_or_failure() {
        let stop = AtomicBool::new(false);
        let mut seen = Vec::new();
        let mut out = Vec::new();
        stream(&mut Cursor::new(b"abc"), &mut out, 3, &stop, &mut |p| seen.push(p)).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(seen, [Progress::Downloading { done: 0, total: 3 }, Progress::Downloading { done: 3, total: 3 }]);
        assert!(stream(&mut Cursor::new(b"ab"), &mut io::sink(), 3, &stop, &mut |_| {}).is_err());
        assert!(stream(&mut Cursor::new(b"abcd"), &mut io::sink(), 3, &stop, &mut |_| {}).is_err());
        let err = stream(&mut Cursor::new(b"abc"), &mut io::sink(), 3, &stop,
            &mut |_| stop.store(true, Ordering::Relaxed)).unwrap_err();
        assert!(err.is::<crate::Stopped>());
    }

    #[test]
    fn store_refuses_symlink_parent_and_reports_insufficient_space() {
        let temp = Staged::new(&std::env::temp_dir()).unwrap();
        let dir = temp.0.join("real");
        let alias = temp.0.join("alias");
        fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&dir, &alias).unwrap();
        let stop = AtomicBool::new(false);
        assert!(store_with(1, &alias, &alias.join("ota.zip"), &stop, |_| panic!("must not write through symlink")).is_err());
        let error = store_with(u64::MAX, &dir, &dir.join("ota.zip"), &stop, |_| panic!("must check space before writing")).unwrap_err();
        assert!(error.is::<NoRoom>());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_file(alias).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn publication_is_private_atomic_and_no_clobber() {
        let temp = Staged::new(&std::env::temp_dir()).unwrap();
        let dir = &temp.0;
        let path = dir.join("ota.zip");
        let stop = AtomicBool::new(false);
        for bytes in [b"ab".as_slice(), b"abcd".as_slice()] {
            assert!(store(&mut Cursor::new(bytes), 3, dir, &path, &stop, &mut |_| {}).is_err());
            assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
        }
        let err = store(&mut Cursor::new(b"abc"), 3, dir, &path, &stop, &mut |p| {
            if p == (Progress::Downloading { done: 3, total: 3 }) { stop.store(true, Ordering::Relaxed); }
        }).unwrap_err();
        assert!(err.is::<crate::Stopped>());
        assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
        stop.store(false, Ordering::Relaxed);
        assert!(store(&mut Cursor::new(b"abc"), 3, dir, &path, &stop, &mut |p| {
            if p == (Progress::Downloading { done: 3, total: 3 }) { fs::write(&path, b"existing").unwrap(); }
        }).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing");
        fs::remove_file(&path).unwrap();
        store(&mut Cursor::new(b"abc"), 3, dir, &path, &stop, &mut |_| {}).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
        fs::remove_file(path).unwrap();
    }

    fn expect_request(listener: &TcpListener, range: &str, etag: Option<&str>, response: &[u8]) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("missing HTTP fixture request: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut read = BufReader::new(&mut socket);
        let mut line = String::new();
        read.read_line(&mut line).unwrap();
        assert_eq!(line, "GET /package HTTP/1.1\r\n");
        let mut headers = std::collections::BTreeMap::new();
        loop {
            line.clear();
            assert_ne!(read.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" { break; }
            let (key, value) = line.split_once(':').unwrap();
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        assert_eq!(headers.get("range").map(String::as_str), Some(range));
        assert_eq!(headers.get("accept-encoding").map(String::as_str), Some("identity"));
        assert_eq!(headers.get("if-range").map(String::as_str), etag);
        socket.write_all(response).unwrap();
    }

    fn loopback() -> (TcpListener, String, ureq::Agent) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/package", listener.local_addr().unwrap());
        let agent = ureq::Agent::config_builder().proxy(None).timeout_global(Some(Duration::from_secs(5))).build().into();
        (listener, url, agent)
    }

    #[test]
    fn capped_responses_are_chained_only_for_the_same_strong_etag() {
        for (first_tag, second, accepted) in [
            ("\"stable\"", Some(("bytes 2-4/5", "\"stable\"")), true),
            ("\"stable\"", Some(("bytes 2-4/5", "\"changed\"")), false),
            ("\"stable\"", Some(("bytes 3-5/6", "\"stable\"")), false),
            ("W/\"weak\"", None, false),
        ] {
            let (listener, url, agent) = loopback();
            let server = std::thread::spawn(move || {
                let first = format!("HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/5\r\nETag: {first_tag}\r\nConnection: close\r\n\r\nab");
                expect_request(&listener, "bytes=0-", None, first.as_bytes());
                if let Some((range, etag)) = second {
                    let last = format!("HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: {range}\r\nETag: {etag}\r\nConnection: close\r\n\r\ncde");
                    expect_request(&listener, "bytes=2-4", Some(first_tag), last.as_bytes());
                }
            });
            let temp = Staged::new(&std::env::temp_dir()).unwrap();
            let path = temp.file();
            let mut seen = Vec::new();
            let got = fetch_from(&agent, &url, &path, &AtomicBool::new(false), &mut |p| seen.push(p));
            server.join().unwrap();
            if accepted {
                got.unwrap();
                assert_eq!(fs::read(path).unwrap(), b"abcde");
                assert_eq!(seen, [Progress::Downloading { done: 0, total: 5 }, Progress::Downloading { done: 2, total: 5 },
                    Progress::Downloading { done: 5, total: 5 }]);
            } else {
                assert!(got.is_err());
                assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0, "no download or scratch file survives");
            }
        }
    }

    #[test]
    fn first_request_is_a_get_from_zero_and_redirect_is_not_followed() {
        for (response, expected) in [
            (b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 0-2/3\r\nConnection: close\r\n\r\nabc".as_slice(), true),
            (b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), false),
        ] {
            let (listener, url, agent) = loopback();
            let server = std::thread::spawn(move || expect_request(&listener, "bytes=0-", None, response));
            let temp = Staged::new(&std::env::temp_dir()).unwrap();
            let path = temp.file();
            let stop = AtomicBool::new(false);
            assert!(fetch(&agent, &url, &path, &stop, &mut |_| {}).is_err(), "public fetch requires HTTPS");
            let got = fetch_from(&agent, &url, &path, &stop, &mut |_| {});
            server.join().unwrap();
            if expected {
                got.unwrap();
                assert_eq!(fs::read(path).unwrap(), b"abc");
            } else {
                assert_eq!(got.unwrap_err().downcast_ref::<Refused>(), Some(&Refused(302)));
                assert!(!path.exists());
            }
        }
    }
}
