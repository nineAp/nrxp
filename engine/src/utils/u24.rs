//! 24-битное беззнаковое целое (3 байта, big-endian).
//!
//! TLS хранит длину handshake-сообщения в 3 байтах — ни `u16`, ни `u32` ровно
//! не подходят. [`U24`] инкапсулирует это представление, а трейт-расширение
//! [`BufExt`] добавляет к любому [`bytes::Buf`] удобный метод
//! [`get_u24`](BufExt::get_u24) для чтения такого поля из потока.

use bytes::Buf;

/// 24-битное целое как три big-endian байта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U24([u8; 3]);

impl U24 {
    /// Берёт младшие 3 байта из `u32` (старший байт отбрасывается).
    pub fn from_u32(value: u32) -> Self {
        let b = value.to_be_bytes();
        U24([b[1], b[2], b[3]])
    }

    /// Расширяет до `u32`, дополняя нулём старший байт. (Пока не используется.)
    pub fn _to_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    /// Читает 24-битное значение из первых трёх байт среза. (Пока не используется.)
    pub fn _from_slice(slice: &[u8]) -> u32 {
        u32::from_be_bytes([0, slice[0], slice[1], slice[2]])
    }
}

/// Расширение [`Buf`]: чтение 24-битного поля из потока байт.
pub trait BufExt: Buf {
    /// Считывает 3 байта big-endian и возвращает их как `u32`.
    fn get_u24(&mut self) -> u32 {
        let b1 = self.get_u8() as u32;
        let b2 = self.get_u8() as u32;
        let b3 = self.get_u8() as u32;
        (b1 << 16) | (b2 << 8) | b3
    }
}

impl<T: Buf> BufExt for T {}
