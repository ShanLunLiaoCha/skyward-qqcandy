//! Bulk request sizing shared by the asynchronous FunctionFS transport and
//! host regressions. The matched MTU3 queue guard rejects above 0xfffc even
//! when its gen2cp error message prints the larger 0xffffc limit. The previous
//! 1 MiB request exceeds both limits.

/// A conservative packet-aligned request size supported by the observed MTU3
/// controller. Keep two asynchronous buffers, not a synchronous USB fallback.
pub const CHUNK: usize = 32 * 1024;

/// Size of the next receive request. OUT reads are packet-aligned, including
/// the final partial payload. The MTP header tracks actual container length.
pub fn receive_request(remaining: Option<u64>, packet: usize) -> usize {
    match remaining {
        Some(left) => (left.min(CHUNK as u64) as usize).next_multiple_of(packet).min(CHUNK),
        None => CHUNK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_fit_mtu3_and_all_advertised_bulk_packet_sizes() {
        const MTU3_MAX: usize = 0xfffc;
        const MTU3_EXTENDED_MAX: usize = 0x0f_fffc;
        assert!(CHUNK <= MTU3_MAX && CHUNK <= MTU3_EXTENDED_MAX);
        assert!(1 << 20 > MTU3_EXTENDED_MAX, "regression: old requests exceed even the extended limit by four bytes");
        assert!(512 * 1024 > MTU3_MAX, "do not use the printed extended limit as the only bound");
        for packet in [64, 512, 1024] {
            assert_eq!(CHUNK % packet, 0);
            for left in [1, 12, 107, 511, 512, 513, 1023, 1024, 4096, 524_287, 524_288, 524_289, 1_048_576, u64::MAX] {
                let request = receive_request(Some(left), packet);
                assert!(request > 0 && request <= CHUNK && request <= MTU3_MAX);
                assert_eq!(request % packet, 0);
                assert!(request as u64 >= left.min(CHUNK as u64));
            }
            assert_eq!(receive_request(None, packet), CHUNK);
        }
    }

    #[test]
    fn packet_padding_does_not_change_the_mtp_container_payload_length() {
        // A SetDevicePropValue data container of 107 bytes still has one
        // packet-aligned receive request; allocation is not its wire length.
        assert_eq!(receive_request(Some(107), 512), 512);
        assert_eq!(receive_request(Some(107), 1024), 1024);
        // A large GetObject sends HEADER+payload through the same bounded
        // buffers; the first buffer's header is counted exactly once.
        const HEADER: usize = 12;
        for payload in [0u64, 1, CHUNK as u64 - 12, CHUNK as u64, 1 << 20, (1u64 << 32) + 7] {
            let first_payload = payload.min((CHUNK - HEADER) as u64);
            let first_request = first_payload + HEADER as u64;
            assert!(first_request <= CHUNK as u64);
            let left = payload - first_payload;
            let full = left / CHUNK as u64;
            let tail = left % CHUNK as u64;
            assert_eq!(first_request + full * CHUNK as u64 + tail, payload + HEADER as u64);
        }
    }
}