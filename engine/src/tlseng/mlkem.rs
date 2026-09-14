//! Генератор правдоподобного `key_share` для гибридной группы `X25519MLKEM768`.
//!
//! ## Зачем это здесь
//!
//! Настоящий Chrome с версии 124 всегда предлагает постквантовую группу, и с
//! конца 2024 это `X25519MLKEM768` (`0x11ec`). Её клиентская доля весит 1216
//! байт и одна определяет размер `ClientHello`: у живого браузера он выходит
//! около 1700 байт и не помещается в один TCP-сегмент. Отпечаток без этой
//! группы не совпадает ни с одним живым Chrome — ни по JA3/JA4, ни по размеру,
//! ни по числу сегментов.
//!
//! Настоящий обмен ключами у нас идёт по X25519 (см. [`crate::crypto`]), так
//! что эти 1216 байт — балласт. Но балласт не может быть случайным.
//!
//! ## Почему нельзя просто насыпать случайных байт
//!
//! Клиентская доля `X25519MLKEM768` — это `ML-KEM-768 ek || X25519 pk`, где
//! `ek` = `ByteEncode₁₂(t̂) || ρ` (1184 = 1152 + 32). В `ByteEncode₁₂` каждая
//! пара 12-битных коэффициентов упакована в 3 байта, и **все 768 коэффициентов
//! обязаны быть меньше q = 3329**. Это не наше требование, а FIPS 203: любой,
//! кто попробует выполнить инкапсуляцию на этот ключ, сначала прогоняет
//! `ByteDecode₁₂` и сверяет результат обратным кодированием — так называемая
//! проверка модуля.
//!
//! Случайные 12-битные слова попадают в [0, 3329) с вероятностью 3329/4096 ≈
//! 0,813, то есть блок из 768 коэффициентов проходит проверку с вероятностью
//! 0,813^768 ≈ 10^-76. Иначе говоря, случайный мусор в этом поле — сам по себе
//! булев детектор с нулём ложных срабатываний, ровно того же класса, что и
//! отсутствие группы. Поэтому коэффициенты сэмплируются в допустимом диапазоне
//! и пакуются по правилам FIPS 203.
//!
//! ## Чего здесь намеренно нет
//!
//! Настоящей ML-KEM: ни `t̂ = Â∘ŝ + ê` не считается, ни `ρ` не порождает
//! матрицу. Ключ структурно валиден, но «пустой» — на нём нельзя выполнить
//! осмысленную инкапсуляцию, а можно только убедиться, что он корректно
//! закодирован. Этого достаточно: инкапсулировать на него никто не будет,
//! потому что до настоящего TLS-сервера этот `ClientHello` не доходит.

use aead::{rand_core::RngCore, OsRng};

/// Модуль ML-KEM (FIPS 203, q = 3329).
const Q: u16 = 3329;
/// Коэффициентов в одном полиноме.
const N: usize = 256;
/// Ранг решётки у ML-KEM-768.
const K: usize = 3;
/// Длина `ByteEncode₁₂(t̂)`: K·N коэффициентов по 12 бит.
const T_HAT_LEN: usize = K * N * 12 / 8; // 1152
/// Длина seed ρ.
const RHO_LEN: usize = 32;
/// Длина encapsulation key ML-KEM-768.
pub(crate) const ML_KEM_768_EK_LEN: usize = T_HAT_LEN + RHO_LEN; // 1184
/// Длина публичного ключа X25519.
const X25519_PK_LEN: usize = 32;
/// Полная длина клиентской доли `X25519MLKEM768` на проводе.
pub(crate) const X25519_MLKEM768_SHARE_LEN: usize = ML_KEM_768_EK_LEN + X25519_PK_LEN; // 1216

/// Упаковывает пары 12-битных коэффициентов в байты по правилам `ByteEncode₁₂`.
///
/// Два коэффициента `a`, `b` дают три байта: `a & 0xff`, `(a >> 8) | (b << 4)`,
/// `b >> 4`. Порядок именно такой (little-endian по битам внутри пары) — от
/// него зависит, пройдёт ли обратное декодирование.
fn byte_encode_12(coeffs: &[u16], out: &mut [u8]) {
    debug_assert_eq!(coeffs.len() % 2, 0);
    debug_assert_eq!(out.len(), coeffs.len() * 12 / 8);

    for (pair, chunk) in coeffs.chunks_exact(2).zip(out.chunks_exact_mut(3)) {
        let (a, b) = (pair[0] as u32, pair[1] as u32);
        chunk[0] = (a & 0xff) as u8;
        chunk[1] = (((a >> 8) & 0x0f) | ((b & 0x0f) << 4)) as u8;
        chunk[2] = ((b >> 4) & 0xff) as u8;
    }
}

/// Равномерный коэффициент в [0, q) методом отбраковки.
///
/// Отбраковка, а не `% Q`: остаток от деления 16-битного случайного числа на
/// 3329 смещён в сторону малых значений (3329 не делит 65536 нацело), и это
/// смещение видно статистически на выборке в тысячи хендшейков — то есть
/// ровно то, чего мы здесь избегаем.
fn sample_coefficient(rng_buf: &mut impl FnMut() -> u16) -> u16 {
    loop {
        let v = rng_buf() & 0x0fff; // 12 бит
        if v < Q {
            return v;
        }
    }
}

/// Собирает клиентскую долю `X25519MLKEM768`: структурно валидный
/// `ML-KEM-768 ek`, за которым следует случайная точка X25519.
///
/// Порядок половин — `ek || X25519`, как задаёт draft-kwiatkowski-tls-ecdhe-mlkem
/// для группы `0x11ec` (у более раннего `X25519Kyber768Draft00` он был обратный;
/// перепутать их — значит выдать себя порядком половин, поэтому здесь он
/// зафиксирован явно).
///
/// Байты свежие на каждый вызов: константный балласт был бы идеальным
/// отпечатком — 1216 одинаковых байт в каждом `ClientHello` узла.
pub(crate) fn sample_x25519_mlkem768_share() -> Vec<u8> {
    let mut entropy = vec![0u8; K * N * 4];
    OsRng.fill_bytes(&mut entropy);
    let mut cursor = 0usize;
    let mut next_u16 = || -> u16 {
        if cursor + 2 > entropy.len() {
            OsRng.fill_bytes(&mut entropy);
            cursor = 0;
        }
        let v = u16::from_le_bytes([entropy[cursor], entropy[cursor + 1]]);
        cursor += 2;
        v
    };

    let mut coeffs = vec![0u16; K * N];
    for c in coeffs.iter_mut() {
        *c = sample_coefficient(&mut next_u16);
    }

    let mut share = vec![0u8; X25519_MLKEM768_SHARE_LEN];
    byte_encode_12(&coeffs, &mut share[..T_HAT_LEN]);
    OsRng.fill_bytes(&mut share[T_HAT_LEN..]); // ρ + X25519 pk

    share
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Обратная операция к [`byte_encode_12`] — то, что выполнит проверяющая
    /// сторона перед проверкой модуля.
    fn byte_decode_12(bytes: &[u8]) -> Vec<u16> {
        let mut out = Vec::with_capacity(bytes.len() * 8 / 12);
        for chunk in bytes.chunks_exact(3) {
            let (b0, b1, b2) = (chunk[0] as u16, chunk[1] as u16, chunk[2] as u16);
            out.push(b0 | ((b1 & 0x0f) << 8));
            out.push((b1 >> 4) | (b2 << 4));
        }
        out
    }

    #[test]
    fn share_has_exactly_the_wire_length_chrome_sends() {
        assert_eq!(sample_x25519_mlkem768_share().len(), 1216);
        assert_eq!(X25519_MLKEM768_SHARE_LEN, 1216);
    }

    #[test]
    fn every_coefficient_passes_the_fips203_modulus_check() {
        // Это и есть проверка, которую провалил бы случайный мусор: шанс
        // пройти её случайно ≈ 0,813^768, то есть примерно 10^-76.
        for _ in 0..64 {
            let share = sample_x25519_mlkem768_share();
            let coeffs = byte_decode_12(&share[..T_HAT_LEN]);
            assert_eq!(coeffs.len(), K * N);
            assert!(
                coeffs.iter().all(|&c| c < Q),
                "encapsulation key обязан декодироваться в коэффициенты < q"
            );
        }
    }

    #[test]
    fn encoding_round_trips_bit_for_bit() {
        // Если упаковка не совпадает с ByteEncode₁₂ побитово, проверяющая
        // сторона получит другие коэффициенты — и модуль может не сойтись
        // даже при корректном сэмплировании.
        let coeffs: Vec<u16> = (0..K * N).map(|i| (i as u16 * 13) % Q).collect();
        let mut buf = vec![0u8; T_HAT_LEN];
        byte_encode_12(&coeffs, &mut buf);
        assert_eq!(byte_decode_12(&buf), coeffs);
    }

    #[test]
    fn ballast_differs_between_handshakes() {
        let a = sample_x25519_mlkem768_share();
        let b = sample_x25519_mlkem768_share();
        assert_ne!(a, b, "константный балласт сам стал бы отпечатком узла");
    }
}
