use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub(crate) fn xof_into(domain: &[u8], parts: &[&[u8]], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

pub(crate) fn xof_array<const N: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; N] {
    let mut output = [0_u8; N];
    xof_into(domain, parts, &mut output);
    output
}

pub(crate) struct BlockStream {
    domain: &'static [u8],
    seed: [u8; 32],
    context: Vec<u8>,
    counter: u64,
    block: [u8; 64],
    offset: usize,
}

impl BlockStream {
    pub(crate) fn new(domain: &'static [u8], seed: &[u8; 32], context: &[u8]) -> Self {
        Self {
            domain,
            seed: *seed,
            context: context.to_vec(),
            counter: 0,
            block: [0_u8; 64],
            offset: 64,
        }
    }

    fn refill(&mut self) {
        self.block = xof_array(
            self.domain,
            &[&self.seed, &self.context, &self.counter.to_le_bytes()],
        );
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }

    pub(crate) fn next_u8(&mut self) -> u8 {
        if self.offset == self.block.len() {
            self.refill();
        }
        let value = self.block[self.offset];
        self.offset += 1;
        value
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        for byte in &mut bytes {
            *byte = self.next_u8();
        }
        u64::from_le_bytes(bytes)
    }

    pub(crate) fn uniform(&mut self, upper: usize) -> usize {
        assert!(upper > 0);
        let upper_u64 = upper as u64;
        let zone = u64::MAX - (u64::MAX % upper_u64);
        loop {
            let value = self.next_u64();
            if value < zone {
                return (value % upper_u64) as usize;
            }
        }
    }
}
