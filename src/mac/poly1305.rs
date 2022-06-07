const rMask0: u64 = 0x0FFFFFFC0FFFFFFF;
const rMask1: u64 = 0x0FFFFFFC0FFFFFFC;

struct macState {
    h: [u64; 3],
    r: [u64; 2],
    s: [u64; 2],
}

impl macState {
    fn new(key: [u8; 32]) -> Self {
        let r = [
            u64::from_le_bytes(key[0..8].try_into().unwrap()) & rMask0,
            u64::from_le_bytes(key[8..16].try_into().unwrap()) & rMask1,
        ];
        let s = [
            u64::from_le_bytes(key[16..24].try_into().unwrap()),
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
        ];

        macState { h: [0u64; 3], r, s }
    }
}
