//! S3 sees keyed identifiers, fixed-length sealed metadata and a padded body.
use super::{bucket_crypto, envelope};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub(crate) const ROOT: &str = ".brows3/objects-v2/";
pub(crate) const HEADER: &str = "brows3-record-v2";
const NAME_BYTES: usize = 1024;
const RECORD_BYTES: usize = 8 + 2 + NAME_BYTES;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid protected object record",
    )
}

fn digest(key: &envelope::Key, domain: &[u8], bucket: &str, name: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("32-byte HMAC key");
    for part in [domain, bucket.as_bytes(), name.as_bytes()] {
        mac.update(part);
        mac.update(&[0]);
    }
    format!("{:x}", mac.finalize().into_bytes())
}

pub(crate) fn listing_prefix(key: &envelope::Key, bucket: &str, prefix: &str) -> String {
    match prefix.split_once('/') {
        Some((top, _)) => format!("{ROOT}{}/", digest(key, b"directory-v2", bucket, top)),
        None => ROOT.to_owned(),
    }
}

pub(crate) fn address(key: &envelope::Key, bucket: &str, name: &str) -> io::Result<String> {
    bucket_crypto::context(bucket, name)?;
    let top = name.split('/').next().ok_or_else(invalid)?;
    Ok(format!(
        "{ROOT}{}/{}",
        digest(key, b"directory-v2", bucket, top),
        digest(key, b"object-v2", bucket, name)
    ))
}

pub(crate) fn valid_address(id: &str) -> bool {
    let Some((top, object)) = id.strip_prefix(ROOT).and_then(|s| s.split_once('/')) else {
        return false;
    };
    [top, object].iter().all(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[derive(Clone)]
pub(crate) struct Record {
    pub name: String,
    pub size: u64,
}

impl Record {
    fn class(&self) -> io::Result<u64> {
        if self.size > envelope::MAX_PLAIN {
            return Err(invalid());
        }
        Ok(self.size.max(4096).next_power_of_two())
    }

    pub(crate) fn stored_size(&self) -> io::Result<u64> {
        Ok(envelope::cipher_size(self.class()?))
    }

    pub(crate) fn seal(&self, key: &envelope::Key, bucket: &str, id: &str) -> io::Result<String> {
        self.class()?;
        if address(key, bucket, &self.name)? != id {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new([0u8; RECORD_BYTES]);
        bytes[..8].copy_from_slice(&self.size.to_le_bytes());
        bytes[8..10].copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        bytes[10..10 + self.name.len()].copy_from_slice(self.name.as_bytes());
        let mut encrypted = Vec::new();
        envelope::encrypt_object(
            &bytes[..],
            &mut encrypted,
            key,
            format!("brows3:record:v2\0{bucket}\0{id}").as_bytes(),
        )?;
        Ok(STANDARD.encode(encrypted))
    }

    pub(crate) fn open(
        key: &envelope::Key,
        bucket: &str,
        id: &str,
        encoded: &str,
    ) -> io::Result<Self> {
        if encoded.len() != (envelope::cipher_size(RECORD_BYTES as u64) as usize).div_ceil(3) * 4
            || !valid_address(id)
        {
            return Err(invalid());
        }
        let ciphertext = STANDARD.decode(encoded).map_err(|_| invalid())?;
        let mut bytes = Zeroizing::new([0u8; RECORD_BYTES]);
        let mut output = &mut bytes[..];
        envelope::decrypt_object(
            &ciphertext[..],
            &mut output,
            key,
            format!("brows3:record:v2\0{bucket}\0{id}").as_bytes(),
        )?;
        if !output.is_empty() {
            return Err(invalid());
        }
        let size = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let n = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
        let name = std::str::from_utf8(bytes.get(10..10 + n).ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_owned();
        let record = Self { name, size };
        if bytes[10 + n..].iter().any(|&v| v != 0) || address(key, bucket, &record.name)? != id {
            return Err(invalid());
        }
        record.class()?;
        Ok(record)
    }

    pub(crate) fn encrypt_body(
        &self,
        mut input: impl Read,
        output: impl Write,
        key: &envelope::Key,
        context: &[u8],
    ) -> io::Result<()> {
        let padding = self.class()? - self.size;
        let mut data = (&mut input).take(self.size);
        envelope::encrypt_object(
            (&mut data).chain(io::repeat(0).take(padding)),
            output,
            key,
            context,
        )?;
        if data.limit() != 0 || input.read(&mut [0])? != 0 {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn decrypt_body(
        &self,
        input: impl Read,
        output: impl Write,
        key: &envelope::Key,
        context: &[u8],
    ) -> io::Result<()> {
        let mut writer = Unpad {
            output,
            remaining: self.size,
            padding: self.class()? - self.size,
        };
        envelope::decrypt_object(input, &mut writer, key, context)?;
        if writer.remaining != 0 || writer.padding != 0 {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) fn body_context(bucket: &str, id: &str, sealed_record: &str) -> Vec<u8> {
    format!("brows3:body:v2\0{bucket}\0{id}\0{sealed_record}").into_bytes()
}

struct Unpad<W> {
    output: W,
    remaining: u64,
    padding: u64,
}
impl<W: Write> Write for Unpad<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.remaining.min(bytes.len() as u64) as usize;
        let pad = &bytes[n..];
        if pad.len() as u64 > self.padding || pad.iter().any(|&v| v != 0) {
            return Err(invalid());
        }
        self.output.write_all(&bytes[..n])?;
        self.remaining -= n as u64;
        self.padding -= pad.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub(crate) fn cursor(
    key: &envelope::Key,
    bucket: &str,
    prefix: &str,
    value: &str,
    encode: bool,
) -> io::Result<String> {
    let context = format!("brows3:list:v2\0{bucket}\0{prefix}");
    let mut out = Vec::new();
    if encode {
        if value.len() > 16_384 {
            return Err(invalid());
        }
        envelope::encrypt_object(value.as_bytes(), &mut out, key, context.as_bytes())?;
        Ok(STANDARD.encode(out))
    } else {
        if value.len() > 24_000 {
            return Err(invalid());
        }
        let input = STANDARD.decode(value).map_err(|_| invalid())?;
        envelope::decrypt_object(&input[..], &mut out, key, context.as_bytes())?;
        String::from_utf8(out).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_records_and_padded_bodies_round_trip_at_size_boundaries() {
        let key = envelope::random_key().unwrap();
        let bucket = format!("b3e1-{}", "a".repeat(32));
        let name = format!("secret/{}", "x".repeat(1017));
        let id = address(&key, &bucket, &name).unwrap();
        assert!(valid_address(&id));
        assert!(!id.contains("secret"));
        let mut header_width = None;
        for size in [0, 1, 4095, 4096, 4097, 65_536, 5_242_880, 7_340_032] {
            let record = Record {
                name: name.clone(),
                size,
            };
            let encoded = record.seal(&key, &bucket, &id).unwrap();
            assert_eq!(*header_width.get_or_insert(encoded.len()), encoded.len());
            let unlocked = Record::open(&key, &bucket, &id, &encoded).unwrap();
            assert_eq!(unlocked.name, name);
            assert_eq!(unlocked.size, size);
            let input = vec![0x79; size as usize];
            let mut cipher = Vec::new();
            let context = body_context(&bucket, &id, &encoded);
            record
                .encrypt_body(&input[..], &mut cipher, &key, &context)
                .unwrap();
            assert_eq!(
                cipher.len() as u64,
                envelope::cipher_size(size.max(4096).next_power_of_two())
            );
            let mut output = Vec::new();
            unlocked
                .decrypt_body(&cipher[..], &mut output, &key, &context)
                .unwrap();
            assert_eq!(output, input);
        }
        let first = Record {
            name: name.clone(),
            size: 5 * 1024 * 1024,
        };
        let second = Record {
            name: "short".into(),
            size: 7 * 1024 * 1024,
        };
        let id2 = address(&key, &bucket, &second.name).unwrap();
        let enc = first.seal(&key, &bucket, &id).unwrap();
        let enc2 = second.seal(&key, &bucket, &id2).unwrap();
        assert_eq!(enc.len(), enc2.len());
        assert_eq!(first.stored_size().unwrap(), second.stored_size().unwrap());
        assert!(Record::open(&key, &bucket, &id2, &enc).is_err());
        assert!(Record::open(&envelope::random_key().unwrap(), &bucket, &id, &enc).is_err());
        assert!(cursor(&key, &bucket, "", "plaintext-name", false).is_err());
    }
}
