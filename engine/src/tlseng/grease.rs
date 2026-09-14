//! GREASE-значения соединения (RFC 8701).
//!
//! ## Что это и почему по одному набору на соединение
//!
//! Chromium подмешивает в `ClientHello` заведомо неизвестные значения вида
//! `0x?a?a`, чтобы серверы не «костенели» на конкретных списках. Мест таких
//! пять, и у BoringSSL для каждого свой независимый жребий, тянущийся один раз
//! на соединение:
//!
//! | Куда | Что кладётся |
//! |------|--------------|
//! | `cipher_suites[0]` | [`cipher`](GreaseSet::cipher) |
//! | `supported_groups[0]` и `key_share[0]` | [`group`](GreaseSet::group) — **одно и то же значение** |
//! | первое расширение | [`ext_first`](GreaseSet::ext_first), нулевой длины |
//! | последнее расширение | [`ext_last`](GreaseSet::ext_last), один байт `0x00` |
//! | `supported_versions[0]` | [`version`](GreaseSet::version) |
//!
//! ## Инвариант, который нельзя нарушить
//!
//! `group` обязано быть **одинаковым** в `supported_groups` и в `key_share`.
//! Настоящий клиент не может предложить долю для группы, которой нет в его же
//! списке поддерживаемых, — расхождение здесь не «менее правдоподобный
//! отпечаток», а нарушение TLS, которого не бывает ни у одного стека. Поэтому
//! значение живёт в одной структуре, а не выбирается дважды по месту.
//!
//! ## Почему набор случайный, а не зашитый в профиль
//!
//! Раньше GREASE-id были константами внутри `ExtensionOrder` (`0xaaaa` у
//! Chrome, `0x1a1a`/`0x3a3a` у Edge). Живой Chromium тянет их заново на каждое
//! соединение: зашитая пара делает JA3 неизменным там, где у браузера он
//! гуляет, — то есть отличает нас от браузера ровно тем механизмом, который
//! был добавлен ради сходства с ним.

use aead::{rand_core::RngCore, OsRng};

/// Все шестнадцать допустимых GREASE-значений (RFC 8701, §3.1).
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Жребий GREASE, вытянутый один раз на соединение.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GreaseSet {
    /// Первый элемент `cipher_suites`.
    pub cipher: u16,
    /// Первая группа в `supported_groups` **и** первая запись `key_share`.
    pub group: u16,
    /// Открывающее список GREASE-расширение (длина 0).
    pub ext_first: u16,
    /// Замыкающее GREASE-расширение (длина 1, значение `0x00`).
    pub ext_last: u16,
    /// Первый элемент `supported_versions`.
    pub version: u16,
}

impl GreaseSet {
    /// Тянет новый набор. Значения независимы: у BoringSSL они выводятся из
    /// одного seed по разным индексам, поэтому совпадения между слотами
    /// случаются и в живом трафике (в снятом захвате `group` и `ext_last`
    /// совпали) — принудительно их разводить было бы наоборот неправдоподобно.
    pub fn random() -> Self {
        let mut b = [0u8; 5];
        OsRng.fill_bytes(&mut b);
        let pick = |i: usize| GREASE_VALUES[(b[i] & 0x0f) as usize];
        Self {
            cipher: pick(0),
            group: pick(1),
            ext_first: pick(2),
            ext_last: pick(3),
            version: pick(4),
        }
    }

    /// Фиксированный набор — только для тестов, где нужна воспроизводимость.
    #[cfg(test)]
    pub fn fixed() -> Self {
        Self {
            cipher: 0xcaca,
            group: 0x8a8a,
            ext_first: 0xdada,
            ext_last: 0x8a8a,
            version: 0xfafa,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlseng::types::TlsExtensions;

    #[test]
    fn every_drawn_value_is_a_valid_grease_value() {
        for _ in 0..256 {
            let g = GreaseSet::random();
            for v in [g.cipher, g.group, g.ext_first, g.ext_last, g.version] {
                assert!(
                    TlsExtensions::is_grease(v),
                    "0x{v:04x} не является GREASE-значением по RFC 8701"
                );
            }
        }
    }

    #[test]
    fn the_draw_actually_varies_between_connections() {
        // Константный набор был бы стабильным JA3 там, где у браузера он
        // меняется, — ровно тот признак, ради устранения которого этот
        // модуль и появился.
        let seen: std::collections::HashSet<u16> =
            (0..256).map(|_| GreaseSet::random().cipher).collect();
        assert!(
            seen.len() > 8,
            "жребий должен покрывать пространство GREASE, а не залипать: {seen:?}"
        );
    }
}
