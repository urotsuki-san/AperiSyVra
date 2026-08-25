use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::matrix::{apply_reverse, decode_secret, derive_trapdoor};
use crate::parameters::{
    CIPHERTEXT_BYTES, CODE_LENGTH, ERROR_WEIGHT, PUBLIC_KEY_BYTES, PUBLIC_KEY_ID_BYTES,
    SECRET_COLUMN_WEIGHT, SECRET_KEY_BYTES, SECRET_SEED_BYTES, SHARED_SECRET_BYTES, SYNDROME_BITS,
    SYNDROME_BYTES,
};
use crate::syndrome::Syndrome;
use crate::xof::xof_array;

const FORMAT_VERSION: u16 = 1;
const PUBLIC_KEY_MAGIC: &[u8; 8] = b"AVPKP1\0\0";
const SECRET_KEY_MAGIC: &[u8; 8] = b"AVSKP1\0\0";
const CIPHERTEXT_MAGIC: &[u8; 8] = b"AVCTP1\0\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    columns: [Syndrome; CODE_LENGTH],
    id: [u8; PUBLIC_KEY_ID_BYTES],
}

#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; SECRET_SEED_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    public_key_id: [u8; PUBLIC_KEY_ID_BYTES],
    syndrome: Syndrome,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SharedSecret([REDACTED])")
    }
}

impl PublicKey {
    pub fn id(&self) -> &[u8; PUBLIC_KEY_ID_BYTES] {
        &self.id
    }

    pub fn columns(&self) -> &[Syndrome; CODE_LENGTH] {
        &self.columns
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut output = [0_u8; PUBLIC_KEY_BYTES];
        output[..8].copy_from_slice(PUBLIC_KEY_MAGIC);
        output[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        output[10..12].copy_from_slice(&(CODE_LENGTH as u16).to_le_bytes());
        output[12..14].copy_from_slice(&(SYNDROME_BITS as u16).to_le_bytes());
        output[14] = ERROR_WEIGHT as u8;
        output[15] = SECRET_COLUMN_WEIGHT as u8;
        output[16..32].copy_from_slice(&self.id);

        for (index, column) in self.columns.iter().enumerate() {
            let offset = 32 + index * SYNDROME_BYTES;
            output[offset..offset + SYNDROME_BYTES].copy_from_slice(&column.to_bytes());
        }
        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidFormat("unexpected public-key length"));
        }
        if &bytes[..8] != PUBLIC_KEY_MAGIC {
            return Err(Error::InvalidFormat("not an AperiSyVra P1 public key"));
        }
        validate_public_parameters(bytes)?;

        let mut id = [0_u8; PUBLIC_KEY_ID_BYTES];
        id.copy_from_slice(&bytes[16..32]);
        let mut columns = [Syndrome::ZERO; CODE_LENGTH];
        for (index, column) in columns.iter_mut().enumerate() {
            let offset = 32 + index * SYNDROME_BYTES;
            *column = Syndrome::from_bytes(&bytes[offset..offset + SYNDROME_BYTES])?;
            if column.is_zero() {
                return Err(Error::InvalidFormat("zero public-key column"));
            }
        }

        if id != public_key_id(&columns) {
            return Err(Error::InvalidFormat("public-key identifier mismatch"));
        }
        Ok(Self { columns, id })
    }
}

impl SecretKey {
    pub fn from_seed(seed: [u8; SECRET_SEED_BYTES]) -> Self {
        Self { seed }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        public_key_from_seed(&self.seed)
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        let mut output = [0_u8; SECRET_KEY_BYTES];
        output[..8].copy_from_slice(SECRET_KEY_MAGIC);
        output[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        output[10..12].fill(0);
        output[12..44].copy_from_slice(&self.seed);
        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(Error::InvalidFormat("unexpected secret-key length"));
        }
        if &bytes[..8] != SECRET_KEY_MAGIC {
            return Err(Error::InvalidFormat("not an AperiSyVra P1 secret key"));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
        if version != FORMAT_VERSION || bytes[10..12] != [0, 0] {
            return Err(Error::InvalidFormat("unsupported secret-key format"));
        }

        let mut seed = [0_u8; SECRET_SEED_BYTES];
        seed.copy_from_slice(&bytes[12..44]);
        Ok(Self { seed })
    }

    pub(crate) fn seed_bytes(&self) -> &[u8; SECRET_SEED_BYTES] {
        &self.seed
    }
}

impl Ciphertext {
    pub fn public_key_id(&self) -> &[u8; PUBLIC_KEY_ID_BYTES] {
        &self.public_key_id
    }

    pub fn syndrome_bytes(&self) -> [u8; SYNDROME_BYTES] {
        self.syndrome.to_bytes()
    }

    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut output = [0_u8; CIPHERTEXT_BYTES];
        output[..8].copy_from_slice(CIPHERTEXT_MAGIC);
        output[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        output[10..12].fill(0);
        output[12..28].copy_from_slice(&self.public_key_id);
        output[28..52].copy_from_slice(&self.syndrome.to_bytes());
        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(Error::InvalidFormat("unexpected ciphertext length"));
        }
        if &bytes[..8] != CIPHERTEXT_MAGIC {
            return Err(Error::InvalidFormat("not an AperiSyVra P1 ciphertext"));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
        if version != FORMAT_VERSION || bytes[10..12] != [0, 0] {
            return Err(Error::InvalidFormat("unsupported ciphertext format"));
        }

        let mut public_key_id = [0_u8; PUBLIC_KEY_ID_BYTES];
        public_key_id.copy_from_slice(&bytes[12..28]);
        let syndrome = Syndrome::from_bytes(&bytes[28..52])?;
        if syndrome.is_zero() {
            return Err(Error::InvalidFormat("zero ciphertext syndrome"));
        }
        Ok(Self {
            public_key_id,
            syndrome,
        })
    }

    pub(crate) fn from_parts(
        public_key_id: [u8; PUBLIC_KEY_ID_BYTES],
        syndrome: Syndrome,
    ) -> Result<Self> {
        if syndrome.is_zero() {
            return Err(Error::InvalidFormat("zero ciphertext syndrome"));
        }
        Ok(Self {
            public_key_id,
            syndrome,
        })
    }

    pub(crate) fn syndrome(&self) -> Syndrome {
        self.syndrome
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

pub fn generate_keypair<R>(rng: &mut R) -> Result<(PublicKey, SecretKey)>
where
    R: RngCore + CryptoRng,
{
    let mut seed = [0_u8; SECRET_SEED_BYTES];
    rng.fill_bytes(&mut seed);
    keypair_from_seed(seed)
}

pub fn keypair_from_seed(seed: [u8; SECRET_SEED_BYTES]) -> Result<(PublicKey, SecretKey)> {
    let public_key = public_key_from_seed(&seed)?;
    Ok((public_key, SecretKey { seed }))
}

pub fn encapsulate<R>(public_key: &PublicKey, rng: &mut R) -> (Ciphertext, SharedSecret)
where
    R: RngCore + CryptoRng,
{
    let positions = draw_error_positions(rng);
    let mut syndrome = Syndrome::ZERO;
    for position in positions {
        syndrome ^= public_key.columns[position];
    }

    let ciphertext = Ciphertext {
        public_key_id: public_key.id,
        syndrome,
    };
    let shared_secret = derive_real_shared_secret(public_key, &ciphertext, positions);
    (ciphertext, shared_secret)
}

pub fn decapsulate(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    let material = derive_trapdoor(&secret_key.seed)?;
    let public_key = PublicKey {
        columns: material.public_columns,
        id: public_key_id(&material.public_columns),
    };
    let fallback = derive_fallback_shared_secret(&secret_key.seed, ciphertext);
    let secret_syndrome = apply_reverse(ciphertext.syndrome, &material.row_ops);

    let Some(decoded) = decode_secret(&material.secret_columns, secret_syndrome) else {
        return Ok(fallback);
    };

    let mut public_positions = decoded
        .positions
        .iter()
        .map(|secret| material.secret_to_public[*secret] as usize)
        .collect::<Vec<_>>();
    public_positions.sort_unstable();
    let Ok(public_positions) = <[usize; ERROR_WEIGHT]>::try_from(public_positions) else {
        return Ok(fallback);
    };

    let mut expected_syndrome = Syndrome::ZERO;
    for position in public_positions {
        expected_syndrome ^= public_key.columns[position];
    }
    if ciphertext.public_key_id != public_key.id || expected_syndrome != ciphertext.syndrome {
        return Ok(fallback);
    }

    Ok(derive_real_shared_secret(
        &public_key,
        ciphertext,
        public_positions,
    ))
}

fn public_key_from_seed(seed: &[u8; SECRET_SEED_BYTES]) -> Result<PublicKey> {
    let material = derive_trapdoor(seed)?;
    let id = public_key_id(&material.public_columns);
    Ok(PublicKey {
        columns: material.public_columns,
        id,
    })
}

fn validate_public_parameters(bytes: &[u8]) -> Result<()> {
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
    let code_length = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed length"));
    let syndrome_bits = u16::from_le_bytes(bytes[12..14].try_into().expect("fixed width"));
    if version != FORMAT_VERSION
        || code_length as usize != CODE_LENGTH
        || syndrome_bits as usize != SYNDROME_BITS
        || bytes[14] as usize != ERROR_WEIGHT
        || bytes[15] as usize != SECRET_COLUMN_WEIGHT
    {
        return Err(Error::UnsupportedParameters);
    }
    Ok(())
}

fn public_key_id(columns: &[Syndrome; CODE_LENGTH]) -> [u8; PUBLIC_KEY_ID_BYTES] {
    let mut encoded = Vec::with_capacity(8 + CODE_LENGTH * SYNDROME_BYTES);
    encoded.extend_from_slice(&(CODE_LENGTH as u16).to_le_bytes());
    encoded.extend_from_slice(&(SYNDROME_BITS as u16).to_le_bytes());
    encoded.push(ERROR_WEIGHT as u8);
    encoded.push(SECRET_COLUMN_WEIGHT as u8);
    for column in columns {
        encoded.extend_from_slice(&column.to_bytes());
    }
    xof_array(b"AperiSyVra/P1/public-key-id/v1", &[&encoded])
}

fn draw_error_positions<R>(rng: &mut R) -> [usize; ERROR_WEIGHT]
where
    R: RngCore + CryptoRng,
{
    let mut positions = [usize::MAX; ERROR_WEIGHT];
    for index in 0..ERROR_WEIGHT {
        loop {
            let candidate = uniform_index(rng, CODE_LENGTH);
            if !positions[..index].contains(&candidate) {
                positions[index] = candidate;
                break;
            }
        }
    }
    positions.sort_unstable();
    positions
}

fn uniform_index<R>(rng: &mut R, upper: usize) -> usize
where
    R: RngCore + CryptoRng,
{
    let upper_u64 = upper as u64;
    let zone = u64::MAX - (u64::MAX % upper_u64);
    loop {
        let value = rng.next_u64();
        if value < zone {
            return (value % upper_u64) as usize;
        }
    }
}

fn derive_real_shared_secret(
    public_key: &PublicKey,
    ciphertext: &Ciphertext,
    positions: [usize; ERROR_WEIGHT],
) -> SharedSecret {
    let mut encoded_positions = Vec::with_capacity(ERROR_WEIGHT * 2);
    for position in positions {
        encoded_positions.extend_from_slice(&(position as u16).to_le_bytes());
    }

    SharedSecret(xof_array(
        b"AperiSyVra/P1/shared-secret/v1",
        &[
            &public_key.id,
            &ciphertext.syndrome.to_bytes(),
            &encoded_positions,
        ],
    ))
}

fn derive_fallback_shared_secret(
    seed: &[u8; SECRET_SEED_BYTES],
    ciphertext: &Ciphertext,
) -> SharedSecret {
    SharedSecret(xof_array(
        b"AperiSyVra/P1/implicit-rejection/v1",
        &[
            seed,
            &ciphertext.public_key_id,
            &ciphertext.syndrome.to_bytes(),
        ],
    ))
}

#[cfg(feature = "research-tools")]
pub mod research {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::{draw_error_positions, SecretKey};
    use crate::error::Result;
    use crate::matrix::{decode_secret, derive_trapdoor, matrix_report};
    use crate::parameters::{CODE_LENGTH, DECODER_MAX_ROUNDS};
    use crate::syndrome::Syndrome;

    #[derive(Clone, Debug)]
    pub struct DecoderStats {
        pub trials: usize,
        pub failures: usize,
        pub average_rounds: f64,
        pub maximum_rounds: usize,
    }

    #[derive(Clone, Debug)]
    pub struct PublicMatrixReport {
        pub minimum_secret_row_degree: usize,
        pub maximum_secret_row_degree: usize,
        pub average_secret_row_degree: f64,
        pub maximum_secret_pair_overlap: usize,
        pub average_public_column_weight: f64,
        pub public_density: f64,
    }

    pub fn decoder_scan(
        secret_seed: [u8; 32],
        random_seed: [u8; 32],
        trials: usize,
    ) -> Result<DecoderStats> {
        let material = derive_trapdoor(&secret_seed)?;
        let mut rng = StdRng::from_seed(random_seed);
        let mut failures = 0_usize;
        let mut total_rounds = 0_usize;
        let mut maximum_rounds = 0_usize;

        for _ in 0..trials {
            let expected = draw_error_positions(&mut rng);
            let mut syndrome = Syndrome::ZERO;
            for position in expected {
                syndrome ^= material.secret_columns[position];
            }

            match decode_secret(&material.secret_columns, syndrome) {
                Some(decoded) if decoded.positions.as_slice() == &expected[..] => {
                    total_rounds += decoded.rounds;
                    maximum_rounds = maximum_rounds.max(decoded.rounds);
                }
                _ => {
                    failures += 1;
                    total_rounds += DECODER_MAX_ROUNDS;
                    maximum_rounds = DECODER_MAX_ROUNDS;
                }
            }
        }

        Ok(DecoderStats {
            trials,
            failures,
            average_rounds: if trials == 0 {
                0.0
            } else {
                total_rounds as f64 / trials as f64
            },
            maximum_rounds,
        })
    }

    pub fn inspect_matrix(secret_key: &SecretKey) -> Result<PublicMatrixReport> {
        let material = derive_trapdoor(secret_key.seed_bytes())?;
        let report = matrix_report(&material);
        Ok(PublicMatrixReport {
            minimum_secret_row_degree: report.minimum_row_degree,
            maximum_secret_row_degree: report.maximum_row_degree,
            average_secret_row_degree: report.average_row_degree,
            maximum_secret_pair_overlap: report.maximum_pair_overlap,
            average_public_column_weight: report.average_public_column_weight,
            public_density: report.public_density,
        })
    }

    pub fn public_column_weight_range(secret_key: &SecretKey) -> Result<(u32, u32)> {
        let material = derive_trapdoor(secret_key.seed_bytes())?;
        let minimum = material
            .public_columns
            .iter()
            .map(|column| column.count_ones())
            .min()
            .unwrap_or(0);
        let maximum = material
            .public_columns
            .iter()
            .map(|column| column.count_ones())
            .max()
            .unwrap_or(0);
        debug_assert_eq!(material.public_columns.len(), CODE_LENGTH);
        Ok((minimum, maximum))
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use super::{decapsulate, encapsulate, keypair_from_seed, Ciphertext, PublicKey, SecretKey};

    #[test]
    fn key_and_ciphertext_formats_round_trip() {
        let (public_key, secret_key) = keypair_from_seed([11_u8; 32]).expect("keypair");
        assert_eq!(
            PublicKey::from_bytes(&public_key.to_bytes()).expect("parse public key"),
            public_key
        );
        let recovered_secret =
            SecretKey::from_bytes(&secret_key.to_bytes()).expect("parse secret key");
        assert_eq!(
            recovered_secret.public_key().expect("derive public key"),
            public_key
        );

        let mut rng = StdRng::from_seed([4_u8; 32]);
        let (ciphertext, _) = encapsulate(&public_key, &mut rng);
        assert_eq!(
            Ciphertext::from_bytes(&ciphertext.to_bytes()).expect("parse ciphertext"),
            ciphertext
        );
    }

    #[test]
    fn encapsulation_round_trip() {
        let (public_key, secret_key) = keypair_from_seed([21_u8; 32]).expect("keypair");
        let mut rng = StdRng::from_seed([5_u8; 32]);
        for _ in 0..16 {
            let (ciphertext, sender_secret) = encapsulate(&public_key, &mut rng);
            let receiver_secret = decapsulate(&secret_key, &ciphertext).expect("decapsulate");
            assert_eq!(sender_secret, receiver_secret);
        }
    }

    #[test]
    fn changed_ciphertext_produces_a_different_secret() {
        let (public_key, secret_key) = keypair_from_seed([31_u8; 32]).expect("keypair");
        let mut rng = StdRng::from_seed([6_u8; 32]);
        let (ciphertext, sender_secret) = encapsulate(&public_key, &mut rng);
        let mut bytes = ciphertext.to_bytes();
        let bit = (rng.next_u32() % 191) as usize;
        bytes[28 + bit / 8] ^= 1_u8 << (bit % 8);
        let modified = Ciphertext::from_bytes(&bytes).expect("modified ciphertext parses");
        let receiver_secret = decapsulate(&secret_key, &modified).expect("decapsulate");
        assert_ne!(sender_secret, receiver_secret);
    }
}
