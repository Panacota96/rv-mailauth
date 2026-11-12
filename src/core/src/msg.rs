//! Outlook .msg (OLE / Compound File Binary, MS-OXMSG): the MAPI properties this tool needs.
//!
//! Variable-length properties are streams named `__substg1.0_<ID><TYPE>` (TYPE 001F = UTF-16LE string,
//! 001E = 8-bit string, 0102 = binary); fixed-size ones (times) are 16-byte entries of the
//! `__properties_version1.0` stream (after a 32-byte header at the root, 8 bytes in an attachment storage).
//! Attachments are storages `__attach_version1.0_#XXXXXXXX`, recipients `__recip_version1.0_#XXXXXXXX`.
//!
//! A .msg does not keep the original MIME message: the body and attachments were re-encoded by Outlook. The
//! original header section survives only in PR_TRANSPORT_MESSAGE_HEADERS (0x007D), and not always.

#![forbid(unsafe_code)]

use crate::model::MsgProperties;
use std::io::{Cursor, Read};

pub const PR_SUBJECT: u16 = 0x0037;
pub const PR_CLIENT_SUBMIT_TIME: u16 = 0x0039;
pub const PR_SENT_REPRESENTING_NAME: u16 = 0x0042;
pub const PR_SENT_REPRESENTING_EMAIL: u16 = 0x0065;
pub const PR_TRANSPORT_MESSAGE_HEADERS: u16 = 0x007D;
pub const PR_SENDER_NAME: u16 = 0x0C1A;
pub const PR_SENDER_EMAIL: u16 = 0x0C1F;
pub const PR_MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
pub const PR_BODY: u16 = 0x1000;
pub const PR_INTERNET_MESSAGE_ID: u16 = 0x1035;
pub const PR_CREATION_TIME: u16 = 0x3007;
pub const PR_LAST_MODIFICATION_TIME: u16 = 0x3008;
pub const PR_ATTACH_DATA_BIN: u16 = 0x3701;
pub const PR_ATTACH_FILENAME: u16 = 0x3704;
pub const PR_ATTACH_LONG_FILENAME: u16 = 0x3707;
pub const PR_ATTACH_MIME_TAG: u16 = 0x370E;

pub const PT_SYSTIME: u16 = 0x0040;
pub const PT_UNICODE: u16 = 0x001F;
pub const PT_STRING8: u16 = 0x001E;
pub const PT_BINARY: u16 = 0x0102;

const MAX_STREAMS_LISTED: usize = 64;
const MAX_ATTACHMENTS: usize = 500;

#[derive(Debug, Default)]
pub struct MsgAttachment {
    pub name: Option<String>,
    pub mime: Option<String>,
    pub data: Vec<u8>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

#[derive(Debug, Default)]
pub struct MsgData {
    pub props: MsgProperties,
    pub transport_headers: Option<String>,
    pub body: Option<String>,
    pub attachments: Vec<MsgAttachment>,
    pub submit_ts: Option<i64>,
    pub delivery_ts: Option<i64>,
}

/// FILETIME (100 ns ticks since 1601-01-01) → seconds since 1970.
pub fn filetime_to_unix(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    Some((ft / 10_000_000) as i64 - 11_644_473_600)
}

fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let s = String::from_utf16_lossy(&units);
    s.trim_end_matches('\0').to_string()
}

type Cfb<'a> = cfb::CompoundFile<Cursor<&'a [u8]>>;

fn read_stream(cf: &mut Cfb, path: &str, max: u64) -> Option<Vec<u8>> {
    let mut s = cf.open_stream(path).ok()?;
    let mut out = Vec::new();
    (&mut s).take(max).read_to_end(&mut out).ok()?;
    Some(out)
}

fn string_prop(cf: &mut Cfb, storage: &str, id: u16, max: u64) -> Option<String> {
    let u = format!("{storage}/__substg1.0_{id:04X}{PT_UNICODE:04X}");
    if let Some(b) = read_stream(cf, &u, max) {
        return Some(utf16le(&b));
    }
    let a = format!("{storage}/__substg1.0_{id:04X}{PT_STRING8:04X}");
    read_stream(cf, &a, max).map(|b| {
        String::from_utf8_lossy(&b)
            .trim_end_matches('\0')
            .to_string()
    })
}

/// Fixed-size properties of one storage: id → 8-byte value, for the given type.
fn fixed_props(cf: &mut Cfb, storage: &str, header: usize, ty: u16) -> Vec<(u16, u64)> {
    let path = format!("{storage}/__properties_version1.0");
    let Some(b) = read_stream(cf, &path, 1 << 20) else {
        return vec![];
    };
    b.get(header..)
        .unwrap_or_default()
        .as_chunks::<16>()
        .0
        .iter()
        .filter_map(|e| {
            let t = u16::from_le_bytes([e[0], e[1]]);
            let id = u16::from_le_bytes([e[2], e[3]]);
            (t == ty).then(|| {
                let mut v = [0u8; 8];
                v.copy_from_slice(&e[8..16]);
                (id, u64::from_le_bytes(v))
            })
        })
        .collect()
}

/// Reads the properties of an Outlook message held in memory. Err = not a usable compound file.
pub fn read(bytes: &[u8], max_stream: u64) -> Result<MsgData, String> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| format!("not a valid compound file: {e}"))?;
    let mut streams: Vec<String> = Vec::new();
    let mut attach_storages: Vec<String> = Vec::new();
    let mut recipients = 0u64;
    for e in cf.walk() {
        let p = e.path().to_string_lossy().replace('\\', "/");
        if e.is_storage() {
            let name = e.name();
            if name.starts_with("__attach_version1.0_#") && p.matches('/').count() == 1 {
                attach_storages.push(p.clone());
            } else if name.starts_with("__recip_version1.0_#") && p.matches('/').count() == 1 {
                recipients += 1;
            }
        } else if streams.len() < MAX_STREAMS_LISTED {
            streams.push(p);
        }
    }
    let root = "";
    let mut d = MsgData::default();
    let th = string_prop(&mut cf, root, PR_TRANSPORT_MESSAGE_HEADERS, max_stream)
        .filter(|s| !s.trim().is_empty());
    d.props.transport_headers = th.is_some();
    d.props.transport_headers_bytes = th.as_ref().map(|s| s.len() as u64).unwrap_or(0);
    d.transport_headers = th;
    d.props.subject = string_prop(&mut cf, root, PR_SUBJECT, 1 << 20);
    d.props.sender_name = string_prop(&mut cf, root, PR_SENDER_NAME, 1 << 16);
    d.props.sender_email = string_prop(&mut cf, root, PR_SENDER_EMAIL, 1 << 16);
    d.props.sent_representing_name = string_prop(&mut cf, root, PR_SENT_REPRESENTING_NAME, 1 << 16);
    d.props.sent_representing_email =
        string_prop(&mut cf, root, PR_SENT_REPRESENTING_EMAIL, 1 << 16);
    d.props.internet_message_id = string_prop(&mut cf, root, PR_INTERNET_MESSAGE_ID, 1 << 16);
    d.body = string_prop(&mut cf, root, PR_BODY, max_stream);
    d.props.body_bytes = d.body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    for (id, v) in fixed_props(&mut cf, root, 32, PT_SYSTIME) {
        match id {
            PR_CLIENT_SUBMIT_TIME => d.submit_ts = filetime_to_unix(v),
            PR_MESSAGE_DELIVERY_TIME => d.delivery_ts = filetime_to_unix(v),
            _ => {}
        }
    }
    d.props.client_submit_time = d.submit_ts.and_then(crate::mail::rfc3339);
    d.props.delivery_time = d.delivery_ts.and_then(crate::mail::rfc3339);
    attach_storages.sort();
    for st in attach_storages.iter().take(MAX_ATTACHMENTS) {
        let mut a = MsgAttachment {
            name: string_prop(&mut cf, st, PR_ATTACH_LONG_FILENAME, 1 << 16)
                .or_else(|| string_prop(&mut cf, st, PR_ATTACH_FILENAME, 1 << 16)),
            mime: string_prop(&mut cf, st, PR_ATTACH_MIME_TAG, 1 << 16),
            data: read_stream(
                &mut cf,
                &format!("{st}/__substg1.0_{PR_ATTACH_DATA_BIN:04X}{PT_BINARY:04X}"),
                max_stream,
            )
            .unwrap_or_default(),
            ..MsgAttachment::default()
        };
        for (id, v) in fixed_props(&mut cf, st, 8, PT_SYSTIME) {
            match id {
                PR_CREATION_TIME => a.created = filetime_to_unix(v),
                PR_LAST_MODIFICATION_TIME => a.modified = filetime_to_unix(v),
                _ => {}
            }
        }
        d.attachments.push(a);
    }
    d.props.attachment_count = attach_storages.len() as u64;
    d.props.recipient_count = recipients;
    d.props.streams = streams;
    Ok(d)
}

/// Writes a minimal .msg (used by the sample generator and the tests; never by the analysis).
pub mod write {
    use super::*;
    use std::io::Write;

    pub struct Prop<'a> {
        pub id: u16,
        pub value: PropValue<'a>,
    }

    pub enum PropValue<'a> {
        Unicode(&'a str),
        Binary(&'a [u8]),
        /// Seconds since 1970 (stored as FILETIME in the properties stream)
        Time(i64),
    }

    pub fn unix_to_filetime(t: i64) -> u64 {
        ((t + 11_644_473_600) as u64) * 10_000_000
    }

    fn write_storage<F: std::io::Read + std::io::Write + std::io::Seek>(
        cf: &mut cfb::CompoundFile<F>,
        storage: &str,
        props: &[Prop],
        header: &[u8],
    ) -> std::io::Result<()> {
        let mut fixed = header.to_vec();
        for p in props {
            match &p.value {
                PropValue::Unicode(s) => {
                    let mut b: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                    b.extend_from_slice(&[0, 0]);
                    let mut st = cf.create_stream(format!(
                        "{storage}/__substg1.0_{:04X}{PT_UNICODE:04X}",
                        p.id
                    ))?;
                    st.write_all(&b)?;
                    // Variable-length entry: type, id, flags, size.
                    fixed.extend_from_slice(&PT_UNICODE.to_le_bytes());
                    fixed.extend_from_slice(&p.id.to_le_bytes());
                    fixed.extend_from_slice(&6u32.to_le_bytes());
                    fixed.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    fixed.extend_from_slice(&0u32.to_le_bytes());
                }
                PropValue::Binary(b) => {
                    let mut st = cf.create_stream(format!(
                        "{storage}/__substg1.0_{:04X}{PT_BINARY:04X}",
                        p.id
                    ))?;
                    st.write_all(b)?;
                    fixed.extend_from_slice(&PT_BINARY.to_le_bytes());
                    fixed.extend_from_slice(&p.id.to_le_bytes());
                    fixed.extend_from_slice(&6u32.to_le_bytes());
                    fixed.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    fixed.extend_from_slice(&0u32.to_le_bytes());
                }
                PropValue::Time(t) => {
                    fixed.extend_from_slice(&PT_SYSTIME.to_le_bytes());
                    fixed.extend_from_slice(&p.id.to_le_bytes());
                    fixed.extend_from_slice(&6u32.to_le_bytes());
                    fixed.extend_from_slice(&unix_to_filetime(*t).to_le_bytes());
                }
            }
        }
        let mut st = cf.create_stream(format!("{storage}/__properties_version1.0"))?;
        st.write_all(&fixed)?;
        Ok(())
    }

    /// A message with root properties and attachments (each a list of properties).
    pub fn message(props: &[Prop], attachments: &[Vec<Prop>]) -> std::io::Result<Vec<u8>> {
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new()))?;
        let mut header = vec![0u8; 8];
        header.extend_from_slice(&0u32.to_le_bytes()); // next recipient id
        header.extend_from_slice(&(attachments.len() as u32).to_le_bytes()); // next attachment id
        header.extend_from_slice(&0u32.to_le_bytes()); // recipient count
        header.extend_from_slice(&(attachments.len() as u32).to_le_bytes()); // attachment count
        header.extend_from_slice(&[0u8; 8]);
        write_storage(&mut cf, "", props, &header)?;
        for (i, a) in attachments.iter().enumerate() {
            let st = format!("/__attach_version1.0_#{i:08X}");
            cf.create_storage(&st)?;
            write_storage(&mut cf, &st, a, &[0u8; 8])?;
        }
        cf.flush()?;
        Ok(cf.into_inner().into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::write::{Prop, PropValue, message};
    use super::*;

    #[test]
    fn round_trip_of_the_properties_read() {
        let b = message(
            &[
                Prop {
                    id: PR_SUBJECT,
                    value: PropValue::Unicode("Factura 7"),
                },
                Prop {
                    id: PR_TRANSPORT_MESSAGE_HEADERS,
                    value: PropValue::Unicode("From: a@example.org\r\nSubject: Factura 7\r\n"),
                },
                Prop {
                    id: PR_CLIENT_SUBMIT_TIME,
                    value: PropValue::Time(1_794_312_000),
                },
            ],
            &[vec![
                Prop {
                    id: PR_ATTACH_LONG_FILENAME,
                    value: PropValue::Unicode("a.txt"),
                },
                Prop {
                    id: PR_ATTACH_DATA_BIN,
                    value: PropValue::Binary(b"hello"),
                },
                Prop {
                    id: PR_LAST_MODIFICATION_TIME,
                    value: PropValue::Time(1_794_315_600),
                },
            ]],
        )
        .unwrap();
        let d = read(&b, 1 << 20).unwrap();
        assert_eq!(d.props.subject.as_deref(), Some("Factura 7"));
        assert!(d.props.transport_headers);
        assert_eq!(d.submit_ts, Some(1_794_312_000));
        assert_eq!(d.attachments.len(), 1);
        assert_eq!(d.attachments[0].data, b"hello");
        assert_eq!(d.attachments[0].name.as_deref(), Some("a.txt"));
        assert_eq!(d.attachments[0].modified, Some(1_794_315_600));
        assert!(read(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1garbage", 1 << 20).is_err());
        // Truncated: an error or a partial read, never a panic.
        let _ = read(&b[..b.len() / 2], 1 << 20);
    }
}
