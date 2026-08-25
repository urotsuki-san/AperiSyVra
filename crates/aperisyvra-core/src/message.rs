use rand::{CryptoRng, RngCore};

use crate::error::{Error, Result};
use crate::kem::{decapsulate, encapsulate, Ciphertext, PublicKey, SecretKey, SharedSecret};
use crate::parameters::{
    MAX_MESSAGE_BYTES, MESSAGE_NONCE_BYTES, MESSAGE_TAG_BYTES, PUBLIC_KEY_ID_BYTES,
    SEALED_HEADER_BYTES, SYNDROME_BYTES,
};
use crate::syndrome::Syndrome;
use crate::xof::{xof_array, xof_into};

const MESSAGE_MAGIC: &[u8; 8] = b"AVMSG1\0\0";
const MESSAGE_VERSION: u16 = 1;
const MESSAGE_FLAGS: u16 = 0;
const MESSAGE_PREFIX_BYTES: usize = 84;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedMessage {
    ciphertext: Ciphertext,
    nonce: [u8; MESSAGE_NONCE_BYTES],
    tag: [u8; MESSAGE_TAG_BYTES],
    body: Vec<u8>,
}

impl SealedMessage {
    pub fn recipient_id(&self) -> &[u8; PUBLIC_KEY_ID_BYTES] {
        self.ciphertext.public_key_id()
    }

    pub fn plaintext_len(&self) -> usize {
        self.body.len()
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let prefix = message_prefix(&self.ciphertext, &self.nonce, self.body.len());
        let mut output = Vec::with_capacity(SEALED_HEADER_BYTES + self.body.len());
        output.extend_from_slice(&prefix);
        output.extend_from_slice(&self.tag);
        output.extend_from_slice(&self.body);
        output
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SEALED_HEADER_BYTES {
            return Err(Error::InvalidFormat("truncated sealed message"));
        }
        if &bytes[..8] != MESSAGE_MAGIC {
            return Err(Error::InvalidFormat("not an AperiSyVra sealed message"));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
        let flags = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed flags"));
        if version != MESSAGE_VERSION || flags != MESSAGE_FLAGS {
            return Err(Error::InvalidFormat("unsupported sealed-message format"));
        }

        let mut public_key_id = [0_u8; PUBLIC_KEY_ID_BYTES];
        public_key_id.copy_from_slice(&bytes[12..28]);
        let syndrome = Syndrome::from_bytes(&bytes[28..28 + SYNDROME_BYTES])?;
        let ciphertext = Ciphertext::from_parts(public_key_id, syndrome)?;

        let mut nonce = [0_u8; MESSAGE_NONCE_BYTES];
        nonce.copy_from_slice(&bytes[52..76]);
        let length = u64::from_le_bytes(bytes[76..84].try_into().expect("fixed length"));
        let length = usize::try_from(length).map_err(|_| Error::LimitExceeded)?;
        if length > MAX_MESSAGE_BYTES || bytes.len() != SEALED_HEADER_BYTES + length {
            return Err(Error::InvalidFormat("sealed-message length mismatch"));
        }

        let mut tag = [0_u8; MESSAGE_TAG_BYTES];
        tag.copy_from_slice(&bytes[84..116]);
        let body = bytes[SEALED_HEADER_BYTES..].to_vec();
        Ok(Self {
            ciphertext,
            nonce,
            tag,
            body,
        })
    }
}

pub fn seal<R>(public_key: &PublicKey, plaintext: &[u8], rng: &mut R) -> Result<SealedMessage>
where
    R: RngCore + CryptoRng,
{
    if plaintext.len() > MAX_MESSAGE_BYTES {
        return Err(Error::LimitExceeded);
    }

    let (ciphertext, shared_secret) = encapsulate(public_key, rng);
    let mut nonce = [0_u8; MESSAGE_NONCE_BYTES];
    rng.fill_bytes(&mut nonce);
    let body = apply_stream(&shared_secret, &ciphertext, &nonce, plaintext);
    let prefix = message_prefix(&ciphertext, &nonce, plaintext.len());
    let tag = message_tag(&shared_secret, &prefix, &body);

    Ok(SealedMessage {
        ciphertext,
        nonce,
        tag,
        body,
    })
}

pub fn open(secret_key: &SecretKey, message: &SealedMessage) -> Result<Vec<u8>> {
    let shared_secret = decapsulate(secret_key, &message.ciphertext)?;
    let prefix = message_prefix(&message.ciphertext, &message.nonce, message.body.len());
    let expected_tag = message_tag(&shared_secret, &prefix, &message.body);
    if !constant_time_eq(&expected_tag, &message.tag) {
        return Err(Error::AuthenticationFailed);
    }

    Ok(apply_stream(
        &shared_secret,
        &message.ciphertext,
        &message.nonce,
        &message.body,
    ))
}

fn message_prefix(
    ciphertext: &Ciphertext,
    nonce: &[u8; MESSAGE_NONCE_BYTES],
    length: usize,
) -> [u8; MESSAGE_PREFIX_BYTES] {
    let mut prefix = [0_u8; MESSAGE_PREFIX_BYTES];
    prefix[..8].copy_from_slice(MESSAGE_MAGIC);
    prefix[8..10].copy_from_slice(&MESSAGE_VERSION.to_le_bytes());
    prefix[10..12].copy_from_slice(&MESSAGE_FLAGS.to_le_bytes());
    prefix[12..28].copy_from_slice(ciphertext.public_key_id());
    prefix[28..52].copy_from_slice(&ciphertext.syndrome().to_bytes());
    prefix[52..76].copy_from_slice(nonce);
    prefix[76..84].copy_from_slice(&(length as u64).to_le_bytes());
    prefix
}

fn apply_stream(
    shared_secret: &SharedSecret,
    ciphertext: &Ciphertext,
    nonce: &[u8; MESSAGE_NONCE_BYTES],
    input: &[u8],
) -> Vec<u8> {
    let mut stream = vec![0_u8; input.len()];
    xof_into(
        b"AperiSyVra/P1/message-stream/v1",
        &[
            shared_secret.as_bytes(),
            ciphertext.public_key_id(),
            &ciphertext.syndrome_bytes(),
            nonce,
            &(input.len() as u64).to_le_bytes(),
        ],
        &mut stream,
    );

    stream
        .into_iter()
        .zip(input.iter().copied())
        .map(|(mask, byte)| mask ^ byte)
        .collect()
}

fn message_tag(
    shared_secret: &SharedSecret,
    prefix: &[u8; MESSAGE_PREFIX_BYTES],
    body: &[u8],
) -> [u8; MESSAGE_TAG_BYTES] {
    xof_array(
        b"AperiSyVra/P1/message-tag/v1",
        &[shared_secret.as_bytes(), prefix, body],
    )
}

fn constant_time_eq(left: &[u8; MESSAGE_TAG_BYTES], right: &[u8; MESSAGE_TAG_BYTES]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= *left ^ *right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::{open, seal, SealedMessage};
    use crate::kem::keypair_from_seed;

    #[test]
    fn message_round_trip() {
        let (public_key, secret_key) = keypair_from_seed([44_u8; 32]).expect("keypair");
        let mut rng = StdRng::from_seed([45_u8; 32]);
        let message = seal(&public_key, b"aperiodic message", &mut rng).expect("seal");
        let encoded = message.to_bytes();
        let decoded = SealedMessage::from_bytes(&encoded).expect("parse message");
        assert_eq!(
            open(&secret_key, &decoded).expect("open"),
            b"aperiodic message"
        );
    }

    #[test]
    fn changed_body_is_rejected() {
        let (public_key, secret_key) = keypair_from_seed([54_u8; 32]).expect("keypair");
        let mut rng = StdRng::from_seed([55_u8; 32]);
        let message = seal(&public_key, b"authenticated", &mut rng).expect("seal");
        let mut encoded = message.to_bytes();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let changed = SealedMessage::from_bytes(&encoded).expect("parse changed message");
        assert!(open(&secret_key, &changed).is_err());
    }
}
