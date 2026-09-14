//! TLS Extensions: сборка (исходящие) и разбор (входящие) — ядро отпечатка.
//!
//! Два направления:
//! - [`ExtensionStack`] + его [`Parser`] — **читают** блок расширений из чужого
//!   hello (нужно, чтобы достать KeyShare с публичным ключом по
//!   [`find_by_type`](ExtensionStack::find_by_type));
//! - [`ExtensionBuilder`] — **пишут** наш блок расширений в точном порядке профиля.
//!
//! Каждое расширение на проводе — это `type(2) | length(2) | data(length)`.
//! Билдер-методы по одному кладут конкретные расширения, а
//! [`apply_profile`](ExtensionBuilder::apply_profile) проходит по
//! [`ExtensionOrder`](super::types::ExtensionOrder) профиля и вызывает нужный
//! метод для каждого id — так гарантируется правильный порядок (JA3/JA4).

use bytes::{Buf, BufMut, Bytes, BytesMut};

use aead::{rand_core::RngCore, OsRng};

use crate::{
    errors::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::{
        consts::{CERT_COMPRESSION_BROTLI, OCSP_STATUS_TYPE, PSK_DHE_KE_MODE, TYPE_HOST_NAME},
        grease::GreaseSet,
        mlkem,
        profile::BrowserProfile,
        types::{TlsExtensions, TlsGroups, TlsSignatures, TlsVersions},
    },
};

/// Одно разобранное расширение: тип + сырые данные (длина продублирована в `_elen`).
#[derive(Debug)]
pub(crate) struct Extension {
    pub etype: u16,
    pub _elen: u16,
    pub data: Bytes,
}

/// Разобранный список расширений из входящего hello.
#[derive(Debug)]
pub(crate) struct ExtensionStack {
    pub extensions: Vec<Extension>,
}

impl ExtensionStack {
    /// Находит расширение по типу и возвращает его данные (zero-copy clone
    /// [`Bytes`]). Главный потребитель — извлечение KeyShare (`0x0033`) с
    /// публичным ключом удалённой стороны при выводе ключей сессии.
    pub fn find_by_type(&self, etype: u16) -> Option<Bytes> {
        self.extensions
            .iter()
            .find(|e| e.etype == etype)
            .map(|e| e.data.clone())
    }

    /// Достаёт hostname из расширения SNI (`server_name`), если оно есть и
    /// синтаксически хорошо сформировано. Формат данных: `list_len(2) |
    /// name_type(1)=0x00 | name_len(2) | name`.
    ///
    /// Нужен серверной stealth-fallback ветке ([`ServerHandler`](crate::net::connection::ServerHandler)):
    /// проксировать «чужого» клиента (невалидный auth-тег) именно на тот хост,
    /// который он сам запросил в SNI, а не всегда на один и тот же фиксированный
    /// decoy — иначе активное зондирование с разными SNI на одном IP всегда
    /// получает одинаковый ответ, что само по себе выдаёт нестандартный прокси.
    /// Возвращаемая строка — сырой ввод удалённой стороны: вызывающий код
    /// обязан провалидировать её (см. `is_plausible_hostname` в `net::connection`)
    /// перед использованием в исходящем сетевом запросе.
    pub fn server_name(&self) -> Option<String> {
        let data = self.find_by_type(TlsExtensions::SNI)?;
        if data.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let list = data.get(2..2 + list_len)?;
        if list.len() < 3 || list[0] != TYPE_HOST_NAME {
            return None;
        }
        let name_len = u16::from_be_bytes([list[1], list[2]]) as usize;
        let name_bytes = list.get(3..3 + name_len)?;
        std::str::from_utf8(name_bytes).ok().map(|s| s.to_string())
    }
}

/// Разбор блока расширений. Сначала «холостым» проходом суммируются длины всех
/// расширений, чтобы убедиться, что блок пришёл целиком и не содержит лишних
/// байт (точное равенство `offset == data_len`); только потом извлекаются сами
/// расширения. Хвостовой мусор → [`ErrorAction::Drop`] (испорченное/чужое hello).
impl Parser for ExtensionStack {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        offset <= data_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        if offset > data_len {
            return Ok(None);
        }

        if offset != data_len {
            return Err(TlsError::new(
                ErrorStage::Tls("Malformed extension stack: trailing data"),
                ErrorAction::Drop,
                Bytes::new(),
            ));
        }

        let mut extensions = Vec::new();
        while bytes.remaining() >= 4 {
            let etype = bytes.get_u16();
            let elen = bytes.get_u16() as usize;
            let data = bytes.split_to(elen).freeze();
            extensions.push(Extension::new(etype, data));
        }

        Ok(Some(Self { extensions }))
    }
}

impl Extension {
    pub fn new(etype: u16, data: Bytes) -> Self {
        Self {
            etype,
            _elen: data.len() as u16,
            data,
        }
    }
}

/// Накопитель блока расширений. Каждый `*`-метод дописывает одно конкретное
/// расширение в `payload`; порядок определяется вызывающим
/// [`apply_profile`](ExtensionBuilder::apply_profile), а не самими методами.
pub(crate) struct ExtensionBuilder {
    payload: BytesMut,
    /// Жребий GREASE этого соединения. Живёт в билдере, а не берётся по месту,
    /// потому что одно и то же значение обязано попасть и в `supported_groups`,
    /// и в `key_share` — см. [`GreaseSet`].
    grease: GreaseSet,
}

impl ExtensionBuilder {
    pub fn new() -> Self {
        Self::with_grease(GreaseSet::random())
    }

    pub fn with_grease(grease: GreaseSet) -> Self {
        Self {
            payload: BytesMut::with_capacity(2048),
            grease,
        }
    }

    /// Низкоуровневая запись одного расширения: `type | len | data`.
    /// Все публичные методы-«рецепты» ниже сводятся к этому вызову.
    fn add_extension(&mut self, etype: u16, data: &[u8]) {
        self.payload.put_u16(etype);
        self.payload.put_u16(data.len() as u16);
        self.payload.put_slice(data);
    }

    /// GREASE-«пустышка»: расширение со случайным id и нулевой длиной (RFC 8701).
    pub fn grease_with_id(&mut self, etype: u16) {
        self.add_extension(etype, &[]);
    }

    pub fn apply_generic_extension(&mut self, etype: u16, _profile: &BrowserProfile) {
        {
            netrunner_logger::trace!(etype, "Applying generic or unknown extension");
        }
    }

    /// SNI (`server_name`): целевой хост в открытом виде — браузеры так и делают,
    /// поэтому для маскировки имя сервера здесь не прячется.
    pub fn server_name(&mut self, host: &str) {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len() as u16;
        let list_inner_len = 1 + 2 + host_len;

        let mut data = BytesMut::with_capacity(2 + list_inner_len as usize);
        data.put_u16(list_inner_len);
        data.put_u8(TYPE_HOST_NAME);
        data.put_u16(host_len);
        data.put_slice(host_bytes);

        self.add_extension(TlsExtensions::SNI, &data);
    }

    pub fn extended_main_secret(&mut self) {
        self.add_extension(TlsExtensions::EMS, &[]);
    }

    /// `supported_groups`. При `has_grease` первым идёт GREASE-значение
    /// соединения — то же самое, что попадёт в `key_share`.
    pub fn supported_groups(&mut self, groups: TlsGroups, has_grease: bool) {
        let extra = usize::from(has_grease);
        let count = groups.0.len() + extra;
        let mut data = BytesMut::with_capacity(2 + count * 2);
        data.put_u16((count * 2) as u16);
        if has_grease {
            data.put_u16(self.grease.group);
        }
        for &g in groups.0 {
            data.put_u16(g);
        }
        self.add_extension(TlsExtensions::SUPPORTED_GROUPS, &data);
    }

    pub fn signature_algorithms(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(TlsExtensions::SIGNATURE_ALGORITHMS, &data);
    }

    /// `supported_versions`. При `has_grease` первым идёт GREASE-версия.
    pub fn supported_versions(&mut self, versions: TlsVersions, has_grease: bool) {
        let extra = usize::from(has_grease);
        let count = versions.0.len() + extra;
        let mut data = BytesMut::with_capacity(1 + count * 2);
        data.put_u8((count * 2) as u8);
        if has_grease {
            data.put_u16(self.grease.version);
        }
        for &v in versions.0 {
            data.put_u16(v);
        }
        self.add_extension(TlsExtensions::SUPPORTED_VERSIONS, &data);
    }

    /// KeyShare (`0x0033`): несёт наш настоящий публичный ключ X25519 — именно
    /// отсюда удалённая сторона достаёт его для ECDH.
    ///
    /// Список записей строится точно как у живого Chromium и в том же порядке,
    /// что и `supported_groups`:
    ///
    /// 1. GREASE-группа соединения с однобайтовым значением `0x00`;
    /// 2. `X25519MLKEM768` — 1216 байт балласта (только если группа есть в
    ///    профиле), см. [`mlkem`];
    /// 3. `x25519` — 32 байта, наш реальный ключ.
    ///
    /// Порядок здесь не косметика: `key_share` обязан идти в том же порядке
    /// предпочтений, что и `supported_groups`, иначе получается клиент,
    /// который предлагает долю для группы раньше, чем саму группу.
    pub fn key_share(&mut self, profile: &BrowserProfile, pub_key: &[u8]) {
        let mut list = BytesMut::with_capacity(1400);

        if profile.has_grease {
            list.put_u16(self.grease.group);
            list.put_u16(1);
            list.put_u8(0x00);
        }

        if profile.groups.0.contains(&TlsGroups::X25519_MLKEM768) {
            let share = mlkem::sample_x25519_mlkem768_share();
            list.put_u16(TlsGroups::X25519_MLKEM768);
            list.put_u16(share.len() as u16);
            list.put_slice(&share);
        }

        list.put_u16(TlsGroups::X25519);
        list.put_u16(pub_key.len() as u16);
        list.put_slice(pub_key);

        let mut data = BytesMut::with_capacity(list.len() + 2);
        data.put_u16(list.len() as u16);
        data.put_slice(&list);

        self.add_extension(TlsExtensions::KEY_SHARE, &data);
    }

    /// GREASE-вариант `encrypted_client_hello` — то, что Chrome шлёт, когда у
    /// него нет настоящего ECHConfig из HTTPS-RR (то есть в подавляющем
    /// большинстве соединений). На проводе он неотличим от настоящего ECH:
    /// это и есть смысл GREASE-режима в draft-ietf-tls-esni.
    ///
    /// Раскладка (всего 186 байт при `payload_len` = 144):
    /// `type(1)=0x00 | kdf(2) | aead(2) | config_id(1) | enc_len(2) | enc(32) |
    /// payload_len(2) | payload`.
    ///
    /// **Длина payload откалибрована по одному захвату.** У настоящего Chrome
    /// она равна длине зашифрованного внутреннего `ClientHello` и потому
    /// зависит от его размера; вывести точную формулу по единственному образцу
    /// нельзя. Константа здесь — компромисс: она правдоподобна, но при
    /// накоплении captures её стоит заменить наблюдаемой зависимостью, иначе
    /// одинаковый размер ECH во всех наших соединениях сам станет признаком.
    pub fn ech_grease(&mut self) {
        const ENC_LEN: usize = 32;
        const PAYLOAD_LEN: usize = 144;

        let mut data = BytesMut::with_capacity(10 + ENC_LEN + PAYLOAD_LEN);
        data.put_u8(0x00); // ECHClientHelloType::outer
        data.put_u16(0x0001); // HKDF-SHA256
        data.put_u16(0x0001); // AES-128-GCM

        let mut rnd = [0u8; 1 + ENC_LEN + PAYLOAD_LEN];
        OsRng.fill_bytes(&mut rnd);

        data.put_u8(rnd[0]); // config_id
        data.put_u16(ENC_LEN as u16);
        data.put_slice(&rnd[1..1 + ENC_LEN]);
        data.put_u16(PAYLOAD_LEN as u16);
        data.put_slice(&rnd[1 + ENC_LEN..]);

        self.add_extension(TlsExtensions::ECH, &data);
    }

    /// ALPS (`application_settings`): формат идентичен `alpn()` — вектор с
    /// 2-байтовой длиной, содержащий длину-префиксные имена протоколов.
    ///
    /// Раньше здесь писался только `len|proto` без внешней 2-байтовой длины
    /// списка, а после каждого имени лишний `put_u16(0)` — на проводе это
    /// давало содержимое вида `02 68 32 00 00`, где Wireshark читает первые
    /// два байта как длину вектора (`0x0268` = 616) и ругается "too large,
    /// truncating it to 3". Реальный Chrome шлёт `00 03 02 68 32`.
    pub fn application_settings(&mut self, protocols: &[&str]) {
        let mut list_data = BytesMut::new();
        for proto in protocols {
            let p_bytes = proto.as_bytes();
            list_data.put_u8(p_bytes.len() as u8);
            list_data.put_slice(p_bytes);
        }
        let mut data = BytesMut::with_capacity(2 + list_data.len());
        data.put_u16(list_data.len() as u16);
        data.put_slice(&list_data);
        self.add_extension(TlsExtensions::ALPS, &data);
    }

    pub fn alpn(&mut self, protocols: &[&str]) {
        let mut list_data = BytesMut::new();
        for proto in protocols {
            let bytes = proto.as_bytes();
            list_data.put_u8(bytes.len() as u8);
            list_data.put_slice(bytes);
        }
        let mut extension_data = BytesMut::new();
        extension_data.put_u16(list_data.len() as u16);
        extension_data.put_slice(&list_data);
        self.add_extension(TlsExtensions::ALPN, &extension_data);
    }

    pub fn psk_key_exchange_modes(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(PSK_DHE_KE_MODE);
        self.add_extension(TlsExtensions::PSK_MODES, &data);
    }

    pub fn compress_certificate(&mut self, algorithms: &[u16]) {
        let mut data = BytesMut::with_capacity(1 + algorithms.len() * 2);
        data.put_u8((algorithms.len() * 2) as u8);
        for &alg in algorithms {
            data.put_u16(alg);
        }
        self.add_extension(TlsExtensions::COMPRESS_CERT, &data);
    }

    pub fn status_request(&mut self) {
        let mut data = BytesMut::with_capacity(5);
        data.put_u8(OCSP_STATUS_TYPE);
        data.put_u16(0);
        data.put_u16(0);
        self.add_extension(TlsExtensions::STATUS_REQUEST, &data);
    }

    pub fn ec_point_formats(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(0x00);
        self.add_extension(TlsExtensions::EC_POINT_FORMATS, &data);
    }

    pub fn signed_certificate_timestamp(&mut self) {
        self.add_extension(TlsExtensions::SCT, &[]);
    }

    pub fn delegated_credential(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(TlsExtensions::DELEGATED_CREDENTIAL, &data);
    }

    pub fn session_ticket(&mut self) {
        self.add_extension(TlsExtensions::SESSION_TICKET, &[]);
    }

    pub fn renegotiation_info(&mut self) {
        self.add_extension(TlsExtensions::RENEGOTIATION_INFO, &[0x00]);
    }

    /// Padding (`0x0015`): добивает `ClientHello` нулями до `target_size` с учётом
    /// `overhead` (заголовки записи/хендшейка и фикс. поля), чтобы итоговая длина
    /// совпала с отпечатком браузера. `-4` — это собственные `type|len` паддинга.
    pub fn padding(&mut self, target_size: usize, overhead: usize) {
        let current_total_size = self.payload.len() + overhead;

        if target_size > current_total_size + 4 {
            let pad_len = target_size - current_total_size - 4;
            let data = vec![0u8; pad_len];
            self.add_extension(TlsExtensions::PADDING, &data);
        }
    }

    /// Перемешивает середину списка расширений (всё, кроме крайних
    /// GREASE-слотов) — Фишер—Йейтс на системной энтропии.
    ///
    /// Chromium перемешивает порядок расширений на каждое соединение начиная с
    /// версии 110. Для нас это не украшение: JA3 считается по порядку, и
    /// фиксированная перестановка дала бы стабильный JA3 там, где у браузера
    /// он гуляет. JA4 сортирует расширения и к перестановке нечувствителен —
    /// поэтому перемешивание совместимо с попаданием в браузерный JA4.
    fn shuffle_middle(order: &mut [u16]) {
        let len = order.len();
        if len < 4 {
            return;
        }
        let middle = &mut order[1..len - 1];
        let mut rnd = vec![0u8; middle.len() * 2];
        OsRng.fill_bytes(&mut rnd);
        for i in (1..middle.len()).rev() {
            let r = u16::from_le_bytes([rnd[i * 2], rnd[i * 2 + 1]]) as usize;
            middle.swap(i, r % (i + 1));
        }
    }

    /// Собирает весь блок расширений по профилю.
    ///
    /// Порядок берётся из [`profile.extension_order`](BrowserProfile::extension_order);
    /// при `profile.shuffle_extensions` середина перемешивается (см.
    /// [`shuffle_middle`](Self::shuffle_middle)), крайние GREASE-слоты остаются
    /// на местах. GREASE-слоты — это маркеры позиции, а не значения: реальные
    /// id подставляются из [`GreaseSet`] этого соединения.
    pub fn apply_profile(
        &mut self,
        profile: &BrowserProfile,
        host: &str,
        pub_key: &[u8],
        overhead: usize,
    ) {
        let mut order: Vec<u16> = profile.extension_order.0.to_vec();
        if profile.shuffle_extensions {
            Self::shuffle_middle(&mut order);
        }

        for ext_id in order {
            match ext_id {
                TlsExtensions::GREASE_SLOT_FIRST => {
                    if profile.has_grease {
                        self.grease_with_id(self.grease.ext_first);
                    }
                }
                TlsExtensions::GREASE_SLOT_LAST => {
                    if profile.has_grease {
                        // У Chrome замыкающее GREASE несёт ровно один байт 0x00,
                        // в отличие от открывающего (нулевой длины).
                        let id = self.grease.ext_last;
                        self.add_extension(id, &[0x00]);
                    }
                }
                TlsExtensions::SNI => self.server_name(host),
                TlsExtensions::SUPPORTED_GROUPS => {
                    self.supported_groups(profile.groups, profile.has_grease)
                }
                TlsExtensions::SIGNATURE_ALGORITHMS => {
                    self.signature_algorithms(profile.signatures)
                }
                TlsExtensions::ALPN => self.alpn(profile.alpn),
                TlsExtensions::SCT => self.signed_certificate_timestamp(),
                TlsExtensions::EMS => self.extended_main_secret(),
                TlsExtensions::ECH => self.ech_grease(),
                TlsExtensions::COMPRESS_CERT => {
                    self.compress_certificate(&[CERT_COMPRESSION_BROTLI])
                }
                TlsExtensions::DELEGATED_CREDENTIAL => {
                    self.delegated_credential(profile.delegated_signatures)
                }
                TlsExtensions::SESSION_TICKET => self.session_ticket(),
                TlsExtensions::SUPPORTED_VERSIONS => {
                    self.supported_versions(profile.versions, profile.has_grease)
                }
                TlsExtensions::PSK_MODES => self.psk_key_exchange_modes(),
                TlsExtensions::KEY_SHARE => self.key_share(profile, pub_key),
                TlsExtensions::ALPS => {
                    if !profile.alps_protocols.is_empty() {
                        self.application_settings(profile.alps_protocols);
                    }
                }
                TlsExtensions::STATUS_REQUEST => self.status_request(),
                TlsExtensions::EC_POINT_FORMATS => self.ec_point_formats(),
                TlsExtensions::RENEGOTIATION_INFO => self.renegotiation_info(),
                TlsExtensions::PADDING => {
                    if profile.target_padding_len > 0 {
                        self.padding(profile.target_padding_len as usize, overhead);
                    }
                }
                id if TlsExtensions::is_grease(id) => {
                    if profile.has_grease {
                        self.grease_with_id(id);
                    }
                }
                _ => self.apply_generic_extension(ext_id, profile),
            }
        }
    }

    /// Завершает сборку и отдаёт готовый блок расширений (zero-copy `freeze`).
    pub fn build(&mut self) -> Bytes {
        self.payload.split().freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlseng::profile::BrowserProfile;

    const FAKE_PUB_KEY: [u8; 32] = [0x7A; 32];

    fn build_for(profile: &BrowserProfile, host: &str) -> ExtensionStack {
        let mut builder = ExtensionBuilder::new();
        builder.apply_profile(profile, host, &FAKE_PUB_KEY, 0);
        let bytes = builder.build();
        ExtensionStack::parse(&mut BytesMut::from(bytes.as_ref()))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn every_browser_profile_round_trips_and_exposes_server_name() {
        for profile in BrowserProfile::ALL {
            let stack = build_for(profile, "example.com");
            assert_eq!(
                stack.server_name().as_deref(),
                Some("example.com"),
                "SNI must round-trip for every profile"
            );

            let key_share = stack
                .find_by_type(TlsExtensions::KEY_SHARE)
                .expect("every profile writes a KeyShare extension");
            // entry: group(2) | key_len(2) | key(32), внутри list_len(2) — итого 4+32=36 после первых 2.
            assert!(key_share.len() >= 36);
            assert_eq!(&key_share[key_share.len() - 32..], &FAKE_PUB_KEY[..]);
        }
    }

    #[test]
    fn server_name_handles_longer_hostnames() {
        let stack = build_for(&BrowserProfile::CHROME_131, "dev.example.com");
        assert_eq!(
            stack.server_name().as_deref(),
            Some("dev.example.com")
        );
    }

    #[test]
    fn server_name_is_none_when_extension_absent() {
        let stack = ExtensionStack { extensions: vec![] };
        assert_eq!(stack.server_name(), None);
    }

    #[test]
    fn server_name_is_none_when_extension_malformed() {
        // list_len врёт про длину — данных после него меньше заявленного.
        let mut data = BytesMut::new();
        data.put_u16(100); // list_len = 100, но данных нет вообще
        let stack = ExtensionStack {
            extensions: vec![Extension::new(TlsExtensions::SNI, data.freeze())],
        };
        assert_eq!(stack.server_name(), None);
    }

    #[test]
    fn server_name_is_none_for_non_utf8_hostname() {
        let mut data = BytesMut::new();
        let name = [0xFFu8, 0xFE, 0xFD];
        data.put_u16((1 + 2 + name.len()) as u16); // list_len
        data.put_u8(TYPE_HOST_NAME);
        data.put_u16(name.len() as u16);
        data.put_slice(&name);
        let stack = ExtensionStack {
            extensions: vec![Extension::new(TlsExtensions::SNI, data.freeze())],
        };
        assert_eq!(stack.server_name(), None);
    }

    #[test]
    fn padding_extension_hits_target_size() {
        let mut builder = ExtensionBuilder::new();
        builder.server_name("example.com");
        let before = builder.payload.len();
        builder.padding(512, 0);
        let after = builder.payload.len();
        assert_eq!(
            after, 512,
            "total size (incl. padding's own 4-byte header) must hit target exactly"
        );
        assert!(after > before);
    }

    #[test]
    fn padding_extension_skipped_when_already_over_target() {
        let mut builder = ExtensionBuilder::new();
        builder.server_name("a-very-long-hostname-that-eats-the-budget.example.com");
        let before = builder.payload.len();
        builder.padding(10, 0); // target already exceeded
        assert_eq!(
            builder.payload.len(),
            before,
            "must not add negative padding"
        );
    }
}
