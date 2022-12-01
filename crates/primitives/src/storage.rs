use super::{StorageKey, StorageValue};
use bytes::Buf;
use modular_bitfield::prelude::*;
use reth_codecs::{use_compact, Compact};

/// Account storage entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[use_compact]
pub struct StorageEntry {
    /// Storage key.
    pub key: StorageKey,
    /// Value on storage key.
    pub value: StorageValue,
}

// impl Compact for StorageEntry {
//     fn to_compact(self, buf: &mut impl bytes::BufMut) -> usize {
//         // let mut flags = StorageEntryFlags::default();
//         let mut total_len = 0;
//         let mut buffer = bytes::BytesMut::new();
//         let _key_len = self.key.to_compact(&mut buffer);
//         let _value_len = self.value.to_compact(&mut buffer);
//         // let flags = flags.into_bytes();
//         total_len = buffer.len();
//         // buf.put_slice(&flags);
//         buf.put(buffer);
//         total_len
//     }
//     fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
//         // let (flags, mut buf) = StorageEntryFlags::from(buf);
//         let mut key = StorageKey::default();
//         (key, buf) = StorageKey::from_compact(buf, buf.len());
//         let mut value = StorageValue::default();
//         (value, buf) = StorageValue::from_compact(buf, buf.len());
//         let obj = StorageEntry {
//             key: key,
//             value: value,
//         };
//         (obj, buf)
//     }
// }
