#![allow(dead_code)]

use bytes::{BufMut, BytesMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;
type WsStream = WebSocketStream<tokio_native_tls::TlsStream<tokio::net::TcpStream>>;
type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

// ============================================================
// #10 — AppLogger с ротацией файла
// ============================================================

pub struct AppLogger {
    path: String,
    file: Mutex<Option<File>>,
    enabled: AtomicBool,
    trace: AtomicBool,
    max_bytes: u64,
    backups: usize,
}

impl AppLogger {
    pub fn new(path: &str, enabled: bool, trace: bool, max_mb: f64, backups: usize) -> Self {
        let file = if enabled {
            OpenOptions::new().create(true).append(true).open(path).ok()
        } else {
            None
        };
        Self {
            path: path.to_string(),
            file: Mutex::new(file),
            enabled: AtomicBool::new(enabled),
            trace: AtomicBool::new(trace),
            max_bytes: (max_mb * 1024.0 * 1024.0) as u64,
            backups,
        }
    }

    pub fn set_enabled(&self, val: bool) {
        self.enabled.store(val, Ordering::Relaxed);
        if let Ok(mut guard) = self.file.lock() {
            if !val {
                *guard = None;
            } else if guard.is_none() {
                if let Ok(new_file) = OpenOptions::new().create(true).append(true).open(&self.path) {
                    *guard = Some(new_file);
                }
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn rotate(&self) {
        // proxy.log.N → удалить, proxy.log.1 → proxy.log.2, ..., proxy.log → proxy.log.1
        let base = PathBuf::from(&self.path);
        for i in (1..=self.backups).rev() {
            let from = if i == 1 {
                base.clone()
            } else {
                PathBuf::from(format!("{}.{}", self.path, i - 1))
            };
            let to = PathBuf::from(format!("{}.{}", self.path, i));
            if i == self.backups {
                let _ = fs::remove_file(&to);
            }
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }
    }

    pub fn log(&self, message: impl AsRef<str>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_secs())
            .unwrap_or(0);
        let line = format!("[{timestamp}] {}", message.as_ref());

        if let Ok(mut guard) = self.file.lock() {
            if guard.is_none() {
                if let Ok(new_file) = OpenOptions::new().create(true).append(true).open(&self.path) {
                    *guard = Some(new_file);
                }
            }

            if let Some(ref mut file) = *guard {
                // Ротация если превышен лимит
                if self.max_bytes > 0 {
                    if let Ok(meta) = file.metadata() {
                        if meta.len() >= self.max_bytes {
                            drop(guard); // освободить lock перед rotate
                            self.rotate();
                            // Переоткрыть файл
                            if let Ok(mut new_guard) = self.file.lock() {
                                if let Ok(new_file) = OpenOptions::new().create(true).append(true).open(&self.path) {
                                    *new_guard = Some(new_file);
                                }
                                if let Some(ref mut f) = *new_guard {
                                    let _ = writeln!(f, "{line}");
                                    let _ = f.flush();
                                }
                            }
                            return;
                        }
                    }
                }
                let _ = writeln!(file, "{line}");
                let _ = file.flush();
            }
        }
    }

    pub fn trace(&self, message: impl AsRef<str>) {
        if self.enabled.load(Ordering::Relaxed) && self.trace.load(Ordering::Relaxed) {
            self.log(message);
        }
    }

    pub fn toggle_trace(&self) -> bool {
        let enabled = !self.trace.load(Ordering::Relaxed);
        self.trace.store(enabled, Ordering::Relaxed);
        enabled
    }

    pub fn trace_enabled(&self) -> bool {
        self.trace.load(Ordering::Relaxed)
    }
}

// ============================================================
// Константы протокола
// ============================================================

const HANDSHAKE_LEN: usize = 64;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const SKIP_LEN: usize = 8;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

const PROTO_ABRIDGED: u32 = 0xEFEFEFEF;
const PROTO_INTERMEDIATE: u32 = 0xEEEEEEEE;
const PROTO_PADDED_INTERMEDIATE: u32 = 0xDDDDDDDD;
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CCS: u8 = 0x14;
const TLS_RECORD_APPDATA: u8 = 0x17;
const TLS_APPDATA_MAX: usize = 16_384;
const TIMESTAMP_TOLERANCE: u64 = 120;
const DEFAULT_SECRET_HEX: &str = "aa6a5bc1c399a42ba92d4448e91df797";

const DEFAULT_DCS: &[(i16, &str)] = &[(2, "149.154.167.220"), (4, "149.154.167.220")];

// #7 — базовый список доменов (обновляется с GitHub в фоне)
const CFPROXY_DEFAULT_DOMAINS: &[&str] = &[
    "pclead.co.uk",
    "offshor.co.uk",
    "cakeisalie.co.uk",
    "noskomnadzor.co.uk",
    "lovetrue.co.uk",
    "sorokdva.co.uk",
    "pyatdesyatdva.co.uk",
    "kartoshka.co.uk",
    "sorokodin.co.uk",
    "pyatdesyatodin.co.uk",
    "notelega.co.uk",
    "ebally.co.uk",
    "nebally.co.uk",
    "havegreatday.co.uk",
    "pomogite.co.uk",
    "fixtelega.co.uk",
    "sadnews.co.uk",
    "onedaychamp.co.uk",
    "stopblocking.co.uk",
    "nothingthere.co.uk",
];

// #7 URL для автообновления доменов (используется в fetch_cf_domains_from_github)
#[allow(dead_code)]
const CFPROXY_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

// #9 — IP тестовых DC
fn default_test_dc_ip(dc: i16) -> Option<&'static str> {
    match dc {
        1 => Some("149.154.175.40"),
        2 => Some("149.154.167.40"),
        3 => Some("149.154.175.117"),
        _ => None,
    }
}

// ============================================================
// Config
// ============================================================

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub secret_hex: String,
    pub dc_redirects: HashMap<i16, String>,
    pub pool_size: usize,
    pub buffer_size: usize,
    pub proxy_protocol: bool,
    pub fallback_cfproxy: bool,
    pub cfproxy_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    pub fake_tls_domain: String,
    pub log_file: String,
    pub log_max_mb: f64,   // #10
    pub log_backups: usize, // #10
    pub prefer_direct_ws: bool,
    pub force_test_dc: bool, // #9
    pub trace: bool,
    pub verbose: bool,
}

impl Config {
    pub fn default_gui() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 1443,
            secret_hex: DEFAULT_SECRET_HEX.to_string(),
            dc_redirects: DEFAULT_DCS
                .iter()
                .map(|(dc, ip)| (*dc, (*ip).to_string()))
                .collect(),
            pool_size: 4,
            buffer_size: 256 * 1024,
            proxy_protocol: false,
            fallback_cfproxy: true,
            cfproxy_domains: Vec::new(),
            cfproxy_worker_domains: Vec::new(),
            fake_tls_domain: "cloudflare.com".to_string(),
            log_file: "proxy.log".to_string(),
            log_max_mb: 5.0,
            log_backups: 1,
            prefer_direct_ws: false,
            force_test_dc: false,
            trace: false,
            verbose: false,
        }
    }

    pub fn parse() -> Result<Self, String> {
        let mut host = "127.0.0.1".to_string();
        let mut port = 1443u16;
        let mut secret_hex: Option<String> = None;
        let mut dc_redirects: HashMap<i16, String> = DEFAULT_DCS
            .iter()
            .map(|(dc, ip)| (*dc, (*ip).to_string()))
            .collect();
        let mut custom_dc_ip = false;
        let mut pool_size = 4usize; // #3 — default изменён с 0 на 4
        let mut buffer_size = 256 * 1024usize;
        let mut proxy_protocol = false;
        let mut fallback_cfproxy = true;
        let mut cfproxy_domains: Vec<String> = Vec::new();
        let mut cfproxy_worker_domains: Vec<String> = Vec::new();
        let mut fake_tls_domain = String::new();
        let mut log_file = "proxy.log".to_string();
        let mut log_max_mb = 5.0f64; // #10
        let mut log_backups = 1usize; // #10
        let mut prefer_direct_ws = false;
        let mut force_test_dc = false; // #9
        let mut trace = false;
        let mut verbose = false;

        let mut args = env::args().skip(1).peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print_help();
                    process::exit(0);
                }
                "--host" => host = take_value(&mut args, "--host")?,
                "--port" => {
                    port = take_value(&mut args, "--port")?
                        .parse()
                        .map_err(|_| "--port must be a number".to_string())?;
                }
                "--secret" => secret_hex = Some(take_value(&mut args, "--secret")?),
                "--dc-ip" => {
                    let value = take_value(&mut args, "--dc-ip")?;
                    if !custom_dc_ip {
                        dc_redirects.clear();
                        custom_dc_ip = true;
                    }
                    let (dc, ip) = parse_dc_ip(&value)?;
                    dc_redirects.insert(dc, ip);
                }
                "--pool-size" => {
                    pool_size = take_value(&mut args, "--pool-size")?
                        .parse()
                        .map_err(|_| "--pool-size must be a number".to_string())?;
                }
                "--buf-kb" => {
                    let kb: usize = take_value(&mut args, "--buf-kb")?
                        .parse()
                        .map_err(|_| "--buf-kb must be a number".to_string())?;
                    buffer_size = kb.max(4) * 1024;
                }
                "--proxy-protocol" => proxy_protocol = true,
                "--no-cfproxy" => fallback_cfproxy = false,
                "--cfproxy-domain" => {
                    cfproxy_domains.push(take_value(&mut args, "--cfproxy-domain")?)
                }
                "--cfproxy-worker-domain" => {
                    cfproxy_worker_domains
                        .push(take_value(&mut args, "--cfproxy-worker-domain")?)
                }
                "--fake-tls-domain" => {
                    fake_tls_domain = take_value(&mut args, "--fake-tls-domain")?
                }
                "--log-file" => log_file = take_value(&mut args, "--log-file")?,
                "--log-max-mb" => {
                    // #10
                    log_max_mb = take_value(&mut args, "--log-max-mb")?
                        .parse()
                        .map_err(|_| "--log-max-mb must be a number".to_string())?;
                }
                "--log-backups" => {
                    // #10
                    log_backups = take_value(&mut args, "--log-backups")?
                        .parse()
                        .map_err(|_| "--log-backups must be a number".to_string())?;
                    log_backups = log_backups.max(1);
                }
                "--prefer-direct-ws" => prefer_direct_ws = true,
                "--force-test-dc" => force_test_dc = true, // #9
                "--trace" => trace = true,
                "--verbose" | "-v" => verbose = true,
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        let secret_hex = match secret_hex {
            Some(s) => s,
            None => DEFAULT_SECRET_HEX.to_string(),
        };

        if secret_hex.len() != 32 || hex::decode(&secret_hex).is_err() {
            return Err("secret must be exactly 32 hex characters".to_string());
        }

        Ok(Self {
            host,
            port,
            secret_hex,
            dc_redirects,
            pool_size,
            buffer_size,
            proxy_protocol,
            fallback_cfproxy,
            cfproxy_domains,
            cfproxy_worker_domains,
            fake_tls_domain,
            log_file,
            log_max_mb,
            log_backups,
            prefer_direct_ws,
            force_test_dc,
            trace,
            verbose,
        })
    }
}

fn take_value(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    name: &str,
) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn parse_dc_ip(value: &str) -> Result<(i16, String), String> {
    let (dc_s, ip_s) = value
        .split_once(':')
        .ok_or_else(|| format!("invalid --dc-ip {value:?}, expected DC:IP"))?;
    let dc: i16 = dc_s
        .parse()
        .map_err(|_| format!("invalid DC in --dc-ip {value:?}"))?;
    ip_s.parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 in --dc-ip {value:?}"))?;
    Ok((dc, ip_s.to_string()))
}

fn print_help() {
    println!("Telegram MTProto WS Bridge Proxy");
    println!();
    println!("Параметры:");
    println!("  --host HOST                IP/host для прослушивания (по умолчанию 127.0.0.1)");
    println!("  --port PORT                Порт прокси (по умолчанию 1443)");
    println!("  --secret HEX               MTProto secret: 32 hex-символа.");
    println!("  --dc-ip DC:IP              IP дата-центра, можно повторять");
    println!("  --pool-size N              Размер пула WS-соединений на DC/media (по умолчанию 4)");
    println!("  --buf-kb KB                Размер TCP-буфера в КБ (по умолчанию 256)");
    println!("  --proxy-protocol           Принимать PROXY protocol v1");
    println!("  --cfproxy-domain NAME      Свой Cloudflare-proxy домен для fallback (можно повторять)");
    println!("  --cfproxy-worker-domain NAME  Cloudflare Worker домен для fallback (можно повторять)");
    println!("  --no-cfproxy               Отключить Cloudflare-proxy fallback");
    println!("  --fake-tls-domain NAME     Включить Fake TLS и вывести ee-ссылку");
    println!("  --log-file PATH            Файл журнала (по умолчанию proxy.log)");
    println!("  --log-max-mb N             Максимальный размер лог-файла в МБ (по умолчанию 5)");
    println!("  --log-backups N            Количество резервных копий лога (по умолчанию 1)");
    println!("  --prefer-direct-ws         Сначала пробовать прямой Telegram WebSocket");
    println!("  --force-test-dc            Перенаправлять весь трафик на тестовые DC Telegram");
    println!("  --trace                    Логировать размеры всех передаваемых фреймов");
    println!("  -v, --verbose              Подробная диагностика соединений");
}

// ============================================================
// #8 — Stats с summary() и human_bytes
// ============================================================

pub fn human_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub struct Stats {
    pub total: AtomicU64,
    pub active: AtomicU64,
    pub bad: AtomicU64,
    pub ws: AtomicU64,
    pub tcp_fallback: AtomicU64,
    pub cf_proxy: AtomicU64,   // #8 новое
    pub masked: AtomicU64,
    pub ws_errors: AtomicU64,  // #8 новое
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
    pub cf_pool_hits: AtomicU64,   // #8 новое
    pub cf_pool_misses: AtomicU64, // #8 новое
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub best_domain: Mutex<String>,
    pub best_ping_ms: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            active: AtomicU64::new(0),
            bad: AtomicU64::new(0),
            ws: AtomicU64::new(0),
            tcp_fallback: AtomicU64::new(0),
            cf_proxy: AtomicU64::new(0),
            masked: AtomicU64::new(0),
            ws_errors: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
            cf_pool_hits: AtomicU64::new(0),
            cf_pool_misses: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            best_domain: Mutex::new(String::new()),
            best_ping_ms: AtomicU64::new(0),
        }
    }

    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn bytes_up(&self) -> u64 {
        self.bytes_up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.bytes_down.load(Ordering::Relaxed)
    }

    pub fn errors(&self) -> u64 {
        self.bad.load(Ordering::Relaxed) + self.ws_errors.load(Ordering::Relaxed)
    }

    pub fn best_domain(&self) -> String {
        self.best_domain.lock().map(|d| d.clone()).unwrap_or_default()
    }

    pub fn best_ping_ms(&self) -> u64 {
        self.best_ping_ms.load(Ordering::Relaxed)
    }

    pub fn set_best_domain(&self, domain: String, ping_ms: u64) {
        if let Ok(mut lock) = self.best_domain.lock() {
            *lock = domain;
        }
        self.best_ping_ms.store(ping_ms, Ordering::Relaxed);
    }

    // #8 — полная строка статистики как в Python
    pub fn summary(&self) -> String {
        let pool_hits = self.pool_hits.load(Ordering::Relaxed);
        let pool_total = pool_hits + self.pool_misses.load(Ordering::Relaxed);
        let pool_s = if pool_total > 0 {
            format!("{pool_hits}/{pool_total}")
        } else {
            "n/a".to_string()
        };
        let cf_hits = self.cf_pool_hits.load(Ordering::Relaxed);
        let cf_total = cf_hits + self.cf_pool_misses.load(Ordering::Relaxed);
        let cf_pool_s = if cf_total > 0 {
            format!("{cf_hits}/{cf_total}")
        } else {
            "n/a".to_string()
        };
        format!(
            "total={} active={} ws={} tcp_fb={} cf={} bad={} masked={} \
             err={} pool={} cf_pool={} up={} down={}",
            self.total.load(Ordering::Relaxed),
            self.active.load(Ordering::Relaxed),
            self.ws.load(Ordering::Relaxed),
            self.tcp_fallback.load(Ordering::Relaxed),
            self.cf_proxy.load(Ordering::Relaxed),
            self.bad.load(Ordering::Relaxed),
            self.masked.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            pool_s,
            cf_pool_s,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
        )
    }
}

// ============================================================
// #5 — FastSplitter O(N): drain один раз в конце
// ============================================================

struct FastSplitter {
    proto: u32,
    plain_buf: Vec<u8>,
    cipher_buf: Vec<u8>,
    disabled: bool,
}

impl FastSplitter {
    fn new(proto_tag: &[u8; 4]) -> Self {
        Self {
            proto: u32::from_be_bytes(*proto_tag),
            plain_buf: Vec::new(),
            cipher_buf: Vec::new(),
            disabled: false,
        }
    }

    // #5 — один drain вместо N drain-ов
    fn split(&mut self, plain_chunk: &[u8], cipher_chunk: &[u8]) -> Vec<Vec<u8>> {
        if plain_chunk.is_empty() {
            return vec![];
        }
        if self.disabled {
            return vec![cipher_chunk.to_vec()];
        }
        self.plain_buf.extend_from_slice(plain_chunk);
        self.cipher_buf.extend_from_slice(cipher_chunk);

        let mut parts = Vec::new();
        let mut total_consumed = 0usize;

        loop {
            let avail = self.plain_buf.len() - total_consumed;
            if avail == 0 {
                break;
            }
            match self.next_packet_len(total_consumed) {
                Some(0) => {
                    // неизвестный протокол → сбросить всё одним куском
                    parts.push(self.cipher_buf[total_consumed..].to_vec());
                    total_consumed = self.cipher_buf.len();
                    self.disabled = true;
                    break;
                }
                Some(packet_len) => {
                    if avail < packet_len {
                        break;
                    }
                    parts.push(
                        self.cipher_buf[total_consumed..total_consumed + packet_len].to_vec(),
                    );
                    total_consumed += packet_len;
                }
                None => break,
            }
        }

        // Один drain в конце — O(N) вместо O(N²)
        if total_consumed > 0 {
            self.cipher_buf.drain(..total_consumed);
            self.plain_buf.drain(..total_consumed);
        }
        parts
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            None
        } else {
            let tail = std::mem::take(&mut self.cipher_buf);
            self.plain_buf.clear();
            Some(tail)
        }
    }

    fn next_packet_len(&self, offset: usize) -> Option<usize> {
        let buf = &self.plain_buf[offset..];
        if buf.is_empty() {
            return None;
        }
        if self.proto == PROTO_ABRIDGED {
            let first = buf[0];
            let (header_len, payload_len) = if first == 0x7f || first == 0xff {
                if buf.len() < 4 {
                    return None;
                }
                let payload_len =
                    u32::from_le_bytes([buf[1], buf[2], buf[3], 0]) as usize * 4;
                (4, payload_len)
            } else {
                (1, ((first as usize) & 0x7f) * 4)
            };
            if payload_len == 0 {
                return Some(0);
            }
            let packet_len = header_len + payload_len;
            if buf.len() < packet_len {
                return None;
            }
            Some(packet_len)
        } else if self.proto == PROTO_INTERMEDIATE || self.proto == PROTO_PADDED_INTERMEDIATE {
            if buf.len() < 4 {
                return None;
            }
            let payload_len =
                (u32::from_le_bytes(buf[0..4].try_into().unwrap()) & 0x7fffffff) as usize;
            if payload_len == 0 {
                return Some(0);
            }
            let packet_len = 4 + payload_len;
            if buf.len() < packet_len {
                return None;
            }
            Some(packet_len)
        } else {
            Some(0)
        }
    }
}

// ============================================================
// #1 — CooldownMap: IP и DC cooldown
// ============================================================

const IP_FAIL_COOLDOWN: Duration = Duration::from_secs(3600); // 1 час
const DC_FAIL_COOLDOWN: Duration = Duration::from_secs(60);   // 1 минута

struct CooldownMap {
    ip_fail_until: Mutex<HashMap<String, Instant>>,
    dc_fail_until: Mutex<HashMap<(i16, bool), Instant>>,
}

impl CooldownMap {
    fn new() -> Self {
        Self {
            ip_fail_until: Mutex::new(HashMap::new()),
            dc_fail_until: Mutex::new(HashMap::new()),
        }
    }

    fn ip_blocked(&self, ip: &str) -> bool {
        self.ip_fail_until
            .lock()
            .unwrap()
            .get(ip)
            .map(|&t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn dc_blocked(&self, dc: i16, is_media: bool) -> bool {
        self.dc_fail_until
            .lock()
            .unwrap()
            .get(&(dc, is_media))
            .map(|&t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn mark_ip_failed(&self, ip: &str) {
        self.ip_fail_until
            .lock()
            .unwrap()
            .insert(ip.to_string(), Instant::now() + IP_FAIL_COOLDOWN);
    }

    fn mark_dc_failed(&self, dc: i16, is_media: bool) {
        self.dc_fail_until
            .lock()
            .unwrap()
            .insert((dc, is_media), Instant::now() + DC_FAIL_COOLDOWN);
    }

    fn clear_ip(&self, ip: &str) {
        self.ip_fail_until.lock().unwrap().remove(ip);
    }

    fn clear_dc(&self, dc: i16, is_media: bool) {
        self.dc_fail_until.lock().unwrap().remove(&(dc, is_media));
    }
}

// ============================================================
// #2 — WsBlacklist: DC с постоянными 302-redirect
// ============================================================

struct WsBlacklist {
    set: Mutex<HashSet<(i16, bool)>>,
}

impl WsBlacklist {
    fn new() -> Self {
        Self {
            set: Mutex::new(HashSet::new()),
        }
    }

    fn is_blacklisted(&self, dc: i16, is_media: bool) -> bool {
        self.set.lock().unwrap().contains(&(dc, is_media))
    }

    fn blacklist(&self, dc: i16, is_media: bool) {
        self.set.lock().unwrap().insert((dc, is_media));
    }
}

// #2 — тип ошибки WS-подключения для различения redirect
enum WsConnectError {
    Redirect,
    Timeout,
    Other(String),
}

// ============================================================
// WsPool
// ============================================================

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PoolKey {
    dc: i16,
    is_media: bool,
}

#[derive(Clone)]
struct WsPool {
    idle: Arc<tokio::sync::Mutex<HashMap<PoolKey, VecDeque<(WsStream, Instant)>>>>,
    pool_size: usize,
}

impl WsPool {
    fn new(pool_size: usize) -> Self {
        Self {
            idle: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pool_size,
        }
    }

    async fn get(&self, key: PoolKey, stats: &Stats) -> Option<WsStream> {
        if self.pool_size == 0 {
            stats.pool_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut map = self.idle.lock().await;
        if let Some(queue) = map.get_mut(&key) {
            while let Some((ws, created)) = queue.pop_front() {
                if created.elapsed().as_secs() < 120 {
                    stats.pool_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(ws);
                }
            }
        }
        stats.pool_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    async fn push(&self, key: PoolKey, ws: WsStream) {
        if self.pool_size == 0 {
            return;
        }
        let mut map = self.idle.lock().await;
        let queue = map
            .entry(key)
            .or_insert_with(|| VecDeque::with_capacity(self.pool_size));
        if queue.len() < self.pool_size {
            queue.push_back((ws, Instant::now()));
        }
    }

    async fn clear(&self) {
        let mut map = self.idle.lock().await;
        map.clear();
    }
}

// ============================================================
// #6 — CfWorkerPool: пул соединений к Cloudflare Worker
// ============================================================

const CF_WORKER_POOL_MAX_AGE: Duration = Duration::from_secs(100);

#[derive(Clone)]
struct CfWorkerPool {
    idle: Arc<tokio::sync::Mutex<HashMap<i16, VecDeque<(WsStream, Instant, String)>>>>,
    pool_size: usize,
}

impl CfWorkerPool {
    fn new(pool_size: usize) -> Self {
        Self {
            idle: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pool_size: pool_size.min(1), // не более 1 на DC (как в Python)
        }
    }

    async fn get(&self, dc: i16, stats: &Stats) -> Option<(WsStream, String)> {
        if self.pool_size == 0 {
            stats.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut map = self.idle.lock().await;
        if let Some(queue) = map.get_mut(&dc) {
            while let Some((ws, created, domain)) = queue.pop_front() {
                if created.elapsed() < CF_WORKER_POOL_MAX_AGE {
                    stats.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                    return Some((ws, domain));
                }
            }
        }
        stats.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    async fn push(&self, dc: i16, ws: WsStream, domain: String) {
        if self.pool_size == 0 {
            return;
        }
        let mut map = self.idle.lock().await;
        let queue = map.entry(dc).or_insert_with(VecDeque::new);
        if queue.len() < self.pool_size {
            queue.push_back((ws, Instant::now(), domain));
        }
    }

    async fn clear(&self) {
        let mut map = self.idle.lock().await;
        map.clear();
    }
}

// ============================================================
// #7 — Динамический список CF-доменов и локальное кэширование
// ============================================================

type CfDomains = Arc<Mutex<Vec<String>>>;

fn decode_cf_domain(s: &str) -> String {
    if !s.ends_with(".com") {
        return s.to_string();
    }
    let p = &s[..s.len() - 4];
    let n = p.chars().filter(|c| c.is_ascii_alphabetic()).count() as u8;
    let mut decoded = String::with_capacity(p.len() + 6);
    for c in p.chars() {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let orig = c as u8 - base;
            let shifted = (orig + 26 - (n % 26)) % 26;
            decoded.push((base + shifted) as char);
        } else {
            decoded.push(c);
        }
    }
    decoded.push_str(".co.uk");
    decoded
}

fn cf_domains_cache_path() -> PathBuf {
    if let Ok(mut exe) = env::current_exe() {
        exe.pop();
        exe.push("cf_domains.cache");
        return exe;
    }
    PathBuf::from("cf_domains.cache")
}

fn load_initial_cf_domains() -> Vec<String> {
    let cache_path = cf_domains_cache_path();
    if let Ok(content) = fs::read_to_string(&cache_path) {
        let cached: Vec<String> = content
            .lines()
            .map(|l| decode_cf_domain(l.trim()))
            .filter(|l| !l.is_empty() && !l.starts_with('#') && is_valid_domain(l))
            .collect();
        if cached.len() >= 3 {
            return cached;
        }
    }
    default_cf_domains()
}

fn save_cf_domains_cache(domains: &[String]) {
    let cache_path = cf_domains_cache_path();
    let content = domains.join("\n");
    let _ = fs::write(cache_path, content);
}

fn default_cf_domains() -> Vec<String> {
    CFPROXY_DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect()
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tld = labels.last().unwrap();
    tld.len() >= 2 && tld.chars().any(|c| c.is_alphabetic())
}

#[derive(Clone)]
pub struct DcBalancer {
    dc_to_domain: Arc<Mutex<HashMap<i16, String>>>,
}

impl DcBalancer {
    pub fn new() -> Self {
        Self {
            dc_to_domain: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_domains_for_dc(&self, dc: i16, sorted_domains: &[String]) -> Vec<String> {
        let mut list = Vec::with_capacity(sorted_domains.len());
        let current = self.dc_to_domain.lock().ok().and_then(|m| m.get(&dc).cloned());
        if let Some(curr) = current {
            list.push(format!("kws{dc}.{curr}"));
            for d in sorted_domains {
                if d != &curr {
                    list.push(format!("kws{dc}.{d}"));
                }
            }
        } else {
            for d in sorted_domains {
                list.push(format!("kws{dc}.{d}"));
            }
        }
        list
    }

    pub fn set_dc_domain(&self, dc: i16, domain: String) {
        if let Ok(mut m) = self.dc_to_domain.lock() {
            m.insert(dc, domain);
        }
    }
}

// Замер задержки к домену
async fn probe_single_domain(domain: String) -> (String, u64) {
    let start = Instant::now();
    let host = format!("kws2.{domain}:443");
    let timeout = Duration::from_millis(1500);
    match tokio::time::timeout(timeout, TcpStream::connect(&host)).await {
        Ok(Ok(stream)) => {
            let rtt = start.elapsed().as_millis() as u64;
            drop(stream);
            (domain, rtt)
        }
        _ => (domain, 9999),
    }
}

pub async fn probe_and_sort_cf_domains(cf_domains: &CfDomains, stats: &Stats, logger: &AppLogger) {
    let domains: Vec<String> = {
        if let Ok(lock) = cf_domains.lock() {
            lock.clone()
        } else {
            return;
        }
    };
    if domains.is_empty() {
        return;
    }

    let mut tasks = Vec::with_capacity(domains.len());
    for d in domains {
        tasks.push(tokio::spawn(probe_single_domain(d)));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(res) = t.await {
            results.push(res);
        }
    }

    results.sort_by_key(|(_domain, ms)| *ms);

    let mut sorted = Vec::with_capacity(results.len());
    let mut best_domain = String::new();
    let mut best_ping = 0u64;

    for (i, (d, ms)) in results.into_iter().enumerate() {
        if i == 0 && ms < 9999 {
            best_domain = d.clone();
            best_ping = ms;
        }
        sorted.push(d);
    }

    if !best_domain.is_empty() {
        stats.set_best_domain(best_domain.clone(), best_ping);
        logger.log(format!(
            "Latency probing: sorted {} domains. Fastest: {} ({} ms)",
            sorted.len(), best_domain, best_ping
        ));
    } else {
        logger.log(format!(
            "Latency probing: sorted {} domains (all unreachable or timed out)",
            sorted.len()
        ));
    }

    if let Ok(mut lock) = cf_domains.lock() {
        *lock = sorted;
    }
}

// Фоновое обновление CF-доменов с GitHub через HTTPS (с fallback на pinned IP)
async fn connect_github_stream() -> Option<TcpStream> {
    if let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect("raw.githubusercontent.com:443"),
    )
    .await
    {
        return Some(stream);
    }
    // Fallback pinned Fastly CDN IP
    if let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect("185.199.109.133:443"),
    )
    .await
    {
        return Some(stream);
    }
    None
}

async fn fetch_cf_domains_from_github() -> Option<Vec<String>> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let tls = make_tls_connector().ok()?;
    let tcp = connect_github_stream().await?;
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        tls.connect("raw.githubusercontent.com", tcp),
    )
    .await
    .ok()?
    .ok()?;

    let (reader, mut writer) = tokio::io::split(tls_stream);
    let request = "GET /Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt HTTP/1.1\r\n\
Host: raw.githubusercontent.com\r\n\
User-Agent: tg-ws-proxy-rust\r\n\
Connection: close\r\n\r\n";
    writer.write_all(request.as_bytes()).await.ok()?;

    let mut lines = BufReader::new(reader).lines();
    let mut in_body = false;
    let mut domains: Vec<String> = Vec::new();

    while let Ok(Some(line)) = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .ok()?
    {
        if !in_body {
            if line.trim().is_empty() {
                in_body = true;
            }
            continue;
        }
        let d = line.trim().to_string();
        if d.is_empty() || d.starts_with('#') {
            continue;
        }
        let decoded = decode_cf_domain(&d);
        if is_valid_domain(&decoded) {
            domains.push(decoded);
        }
    }

    if domains.len() >= 3 {
        Some(domains)
    } else {
        None
    }
}

fn start_cf_domain_refresh(
    cf_domains: CfDomains,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        // Быстрый первичный замер задержки текущего кэша доменов
        probe_and_sort_cf_domains(&cf_domains, &stats, &logger).await;

        // Немедленная первая попытка обновления списка с GitHub
        if let Some(fresh) = fetch_cf_domains_from_github().await {
            let count = fresh.len();
            save_cf_domains_cache(&fresh);
            if let Ok(mut lock) = cf_domains.lock() {
                *lock = fresh;
            }
            logger.log(format!(
                "CF proxy domain pool updated from GitHub ({count} domains)"
            ));
            probe_and_sort_cf_domains(&cf_domains, &stats, &logger).await;
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3600)) => {
                    match fetch_cf_domains_from_github().await {
                        Some(fresh) => {
                            let count = fresh.len();
                            save_cf_domains_cache(&fresh);
                            if let Ok(mut lock) = cf_domains.lock() {
                                *lock = fresh;
                            }
                            logger.log(format!(
                                "CF proxy domain pool refreshed from GitHub ({count} domains)"
                            ));
                            probe_and_sort_cf_domains(&cf_domains, &stats, &logger).await;
                        }
                        None => {
                            logger.log(
                                "CF proxy domain refresh failed or empty response; re-probing current pool"
                                    .to_string(),
                            );
                            probe_and_sort_cf_domains(&cf_domains, &stats, &logger).await;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });
}

// ============================================================
// WS connect functions
// ============================================================

async fn connect_ws(
    target_ip: &str,
    domain: &str,
    tls: &TokioTlsConnector,
) -> Result<WsStream, String> {
    let tcp_stream = TcpStream::connect(format!("{target_ip}:443"))
        .await
        .map_err(|e| e.to_string())?;
    set_tcp_options(&tcp_stream, None);
    let tls_stream = tls
        .connect(domain, tcp_stream)
        .await
        .map_err(|e| e.to_string())?;
    let ws_url = format!("wss://{domain}/apiws");
    let request = http::Request::builder()
        .uri(&ws_url)
        .header("Host", domain)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", "binary")
        .body(())
        .map_err(|e| e.to_string())?;
    let (ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ws_stream)
}

fn ws_domains(dc: i16, is_media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if is_media {
        vec![
            format!("kws{dc}-1.web.telegram.org"),
            format!("kws{dc}.web.telegram.org"),
        ]
    } else {
        vec![format!("kws{dc}.web.telegram.org")]
    }
}

fn make_tls_connector() -> Result<TokioTlsConnector, String> {
    Ok(TokioTlsConnector::from(
        tokio_native_tls::native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| e.to_string())?,
    ))
}

// #2 — connect с различением типа ошибки
async fn connect_ws_typed(
    target_ip: &str,
    domain: &str,
    tls: &TokioTlsConnector,
) -> Result<WsStream, WsConnectError> {
    match tokio::time::timeout(Duration::from_secs(10), connect_ws(target_ip, domain, tls)).await {
        Ok(Ok(ws)) => Ok(ws),
        Ok(Err(err)) => {
            // Detect HTTP redirect errors from tungstenite
            let s = err.to_lower_ascii();
            if s.contains("301") || s.contains("302") || s.contains("redirect") {
                Err(WsConnectError::Redirect)
            } else {
                Err(WsConnectError::Other(err))
            }
        }
        Err(_) => Err(WsConnectError::Timeout),
    }
}

// Вспомогательный трейт для lowercase ASCII
trait ToLowerAscii {
    fn to_lower_ascii(&self) -> String;
}
impl ToLowerAscii for String {
    fn to_lower_ascii(&self) -> String {
        self.to_ascii_lowercase()
    }
}

async fn connect_ws_any(target_ip: &str, domains: &[String]) -> Result<WsStream, String> {
    let tls = make_tls_connector()?;
    let mut last_err = "no domains".to_string();
    for domain in domains {
        match tokio::time::timeout(Duration::from_secs(10), connect_ws(target_ip, domain, &tls))
            .await
        {
            Ok(Ok(ws)) => return Ok(ws),
            Ok(Err(err)) => last_err = err,
            Err(_) => last_err = format!("timeout connecting to {domain}"),
        }
    }
    Err(last_err)
}

// ============================================================
// #3 — pool_worker с exponential backoff
// ============================================================

async fn pool_worker(
    pool: WsPool,
    key: PoolKey,
    target_ip: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut failures: u32 = 0;
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let current_len = {
            let map = pool.idle.lock().await;
            map.get(&key).map(|q| q.len()).unwrap_or(0)
        };
        if current_len < pool.pool_size {
            let domains = ws_domains(key.dc, key.is_media);
            tokio::select! {
                res = connect_ws_any(&target_ip, &domains) => {
                    match res {
                        Ok(ws) => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                            pool.push(key, ws).await;
                            failures = 0; // сброс при успехе
                        }
                        Err(_) => {
                            failures += 1;
                            // backoff: 60s * 2^(failures-1), max 3600s
                            let delay_secs: u64 =
                                (60u64 * (1u64 << failures.saturating_sub(1).min(6))).min(3600);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {}
                                _ = shutdown_rx.changed() => { break; }
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        } else {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                _ = shutdown_rx.changed() => { break; }
            }
        }
    }
}

// ============================================================
// run_proxy_server
// ============================================================

pub async fn run_proxy_server(
    config: Arc<Config>,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let secret = hex::decode(&config.secret_hex)
        .map_err(|e| format!("invalid secret hex: {e}"))?;
    let secret_arc = Arc::new(secret);
    let addr = format!("{}:{}", config.host, config.port);

    logger.log(format!(
        "startup: listening={addr}, configured_dc={:?}, pool_size={}, fake_tls={}, \
         prefer_direct_ws={}, force_test_dc={}, trace={}, verbose={}, log_file={} (max={:.1}MB, backups={})",
        config.dc_redirects.keys().collect::<Vec<_>>(),
        config.pool_size,
        !config.fake_tls_domain.is_empty(),
        config.prefer_direct_ws,
        config.force_test_dc,
        config.trace,
        config.verbose,
        config.log_file,
        config.log_max_mb,
        config.log_backups,
    ));

    // #1 — глобальный cooldown
    let cooldown = Arc::new(CooldownMap::new());
    // #2 — глобальный blacklist
    let blacklist = Arc::new(WsBlacklist::new());
    // #7 — динамические CF-домены (загрузка из локального кэша или базового списка)
    let cf_domains: CfDomains = Arc::new(Mutex::new(load_initial_cf_domains()));
    if config.cfproxy_domains.is_empty() {
        start_cf_domain_refresh(cf_domains.clone(), stats.clone(), logger.clone(), shutdown_rx.clone());
    }
    // DC Balancer с привязкой доменов
    let dc_balancer = Arc::new(DcBalancer::new());
    // #6 — CF Worker pool
    let cf_worker_pool = Arc::new(CfWorkerPool::new(config.pool_size));

    let listener = TcpListener::bind(&addr).await?;
    let pool = WsPool::new(config.pool_size);

    if config.pool_size > 0 {
        for (dc, ip) in config.dc_redirects.clone() {
            for is_media in [false, true] {
                let p = pool.clone();
                let key = PoolKey { dc, is_media };
                let target_ip = ip.clone();
                let s_rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    pool_worker(p, key, target_ip, s_rx).await;
                });
            }
        }
    }

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _peer_addr)) => {
                        set_tcp_options(&stream, Some(config.buffer_size));
                        let sec = secret_arc.clone();
                        let p = pool.clone();
                        let cfg = config.clone();
                        let stats = stats.clone();
                        let logger = logger.clone();
                        let cooldown = cooldown.clone();
                        let blacklist = blacklist.clone();
                        let cf_domains = cf_domains.clone();
                        let cf_worker_pool = cf_worker_pool.clone();
                        let dc_balancer = dc_balancer.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_client(
                                stream, sec, p, cfg, stats, logger.clone(),
                                cooldown, blacklist, cf_domains, cf_worker_pool,
                                dc_balancer,
                            )
                            .await
                            {
                                logger.log(format!("client session failed: {err}"));
                            }
                        });
                    }
                    Err(e) => {
                        logger.log(format!("accept error: {e}"));
                    }
                }
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    logger.log("proxy server shutdown received");
                    break;
                }
            }
        }
    }

    // Очистка пулов соединений при остановке прокси (закрытие idle сокетов)
    pool.clear().await;
    cf_worker_pool.clear().await;

    Ok(())
}

pub fn open_url(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = process::Command::new("rundll32")
            .arg("url.dll,FileProtocolHandler")
            .arg(url)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = process::Command::new("xdg-open").arg(url).spawn();
    }
}

pub fn link_host(host: &str) -> String {
    if host != "0.0.0.0" {
        return host.to_string();
    }
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("8.8.8.8:80")?;
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn set_tcp_options(stream: &TcpStream, _buffer_size: Option<usize>) {
    let _ = stream.set_nodelay(true);
}

// ============================================================
// handle_client
// ============================================================

#[allow(clippy::too_many_arguments)]
async fn handle_client(
    client_stream: TcpStream,
    secret: Arc<Vec<u8>>,
    pool: WsPool,
    config: Arc<Config>,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    cooldown: Arc<CooldownMap>,
    blacklist: Arc<WsBlacklist>,
    cf_domains: CfDomains,
    cf_worker_pool: Arc<CfWorkerPool>,
    dc_balancer: Arc<DcBalancer>,
) -> Result<(), Box<dyn std::error::Error>> {
    stats.total.fetch_add(1, Ordering::Relaxed);
    stats.active.fetch_add(1, Ordering::Relaxed);
    let result = handle_client_inner(
        client_stream, secret, pool, config, stats.clone(), logger,
        cooldown, blacklist, cf_domains, cf_worker_pool, dc_balancer,
    )
    .await;
    stats.active.fetch_sub(1, Ordering::Relaxed);
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_inner(
    mut client_stream: TcpStream,
    secret: Arc<Vec<u8>>,
    pool: WsPool,
    config: Arc<Config>,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    cooldown: Arc<CooldownMap>,
    blacklist: Arc<WsBlacklist>,
    cf_domains: CfDomains,
    cf_worker_pool: Arc<CfWorkerPool>,
    dc_balancer: Arc<DcBalancer>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut label = client_stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    logger.log(format!("[{label}] client connected"));

    if config.proxy_protocol {
        if let Some(proxy_label) = read_proxy_protocol(&mut client_stream).await? {
            label = proxy_label;
            logger.log(format!("[{label}] PROXY protocol accepted"));
        } else {
            logger.log(format!(
                "[{label}] PROXY protocol header missing or invalid"
            ));
        }
    }

    let (handshake, clt_read, clt_write) =
        match read_client_init(client_stream, &secret, &config, &label, &stats, &logger).await? {
            Some(init) => init,
            None => {
                logger.log(format!(
                    "[{label}] client initialization was rejected or timed out"
                ));
                return Ok(());
            }
        };

    let parsed = match parse_handshake(&handshake, &secret) {
        Some(parsed) => parsed,
        None => {
            stats.bad.fetch_add(1, Ordering::Relaxed);
            logger.log(format!("[{label}] invalid MTProto handshake"));
            return Ok(());
        }
    };

    // #9 — Test DC: raw_dc >= 10000
    let raw_dc = parsed.dc;
    let is_test_dc = config.force_test_dc || raw_dc >= 10000;
    let requested_dc = if raw_dc >= 10000 { raw_dc - 10000 } else { raw_dc };

    if is_test_dc && raw_dc >= 10000 {
        logger.log(format!("[{label}] test DC{raw_dc} → DC{requested_dc}"));
    }

    let route_dc = if requested_dc == 203 { 2 } else { requested_dc };
    let has_explicit_requested_dc = config.dc_redirects.contains_key(&requested_dc);
    let ws_enabled = has_explicit_requested_dc && !is_test_dc;

    let target_ip = if has_explicit_requested_dc {
        config
            .dc_redirects
            .get(&requested_dc)
            .expect("checked above")
            .clone()
    } else if is_test_dc {
        default_test_dc_ip(requested_dc)  // #9
            .or_else(|| default_test_dc_ip(route_dc))
            .unwrap_or("149.154.167.40")
            .to_string()
    } else {
        default_dc_ip(requested_dc)
            .or_else(|| default_dc_ip(route_dc))
            .unwrap_or("149.154.167.220")
            .to_string()
    };

    let dc_idx = if parsed.is_media {
        -requested_dc
    } else {
        requested_dc
    };
    let relay_init = generate_relay_init(parsed.proto_tag, dc_idx);
    let crypto = build_crypto(&handshake, &secret, &relay_init);
    let key = PoolKey {
        dc: requested_dc,
        is_media: parsed.is_media,
    };
    let domains = ws_domains(requested_dc, parsed.is_media);

    logger.log(format!(
        "[{label}] MTProto handshake accepted: dc={requested_dc}, media={}, \
         proto=0x{:08X}, ws_enabled={ws_enabled}, test_dc={is_test_dc}, target={target_ip}:443",
        parsed.is_media,
        u32::from_be_bytes(parsed.proto_tag)
    ));

    // Если DC не настроен для WS или тестовый — сразу fallback
    if !ws_enabled {
        logger.log(format!(
            "[{label}] DC{requested_dc} skipping WS (ws_enabled={ws_enabled}, test_dc={is_test_dc}); using fallback"
        ));
        return bridge_fallback(
            clt_read, clt_write, &target_ip, requested_dc, is_test_dc,
            relay_init, crypto, parsed.proto_tag,
            config, stats, logger, label, cf_domains, cf_worker_pool,
            dc_balancer,
        )
        .await;
    }

    // #1 — проверяем cooldown
    if cooldown.ip_blocked(&target_ip) || cooldown.dc_blocked(requested_dc, parsed.is_media) {
        logger.log(format!(
            "[{label}] DC{requested_dc} in cooldown; skipping WS, using fallback"
        ));
        return bridge_fallback(
            clt_read, clt_write, &target_ip, requested_dc, is_test_dc,
            relay_init, crypto, parsed.proto_tag,
            config, stats, logger, label, cf_domains, cf_worker_pool,
            dc_balancer.clone(),
        )
        .await;
    }

    // #2 — проверяем blacklist
    if blacklist.is_blacklisted(requested_dc, parsed.is_media) {
        logger.log(format!(
            "[{label}] DC{requested_dc} blacklisted (all 302); using fallback"
        ));
        return bridge_fallback(
            clt_read, clt_write, &target_ip, requested_dc, is_test_dc,
            relay_init, crypto, parsed.proto_tag,
            config, stats, logger, label, cf_domains, cf_worker_pool,
            dc_balancer.clone(),
        )
        .await;
    }

    // Пул
    if let Some(ws) = pool.get(key, &stats).await {
        logger.log(format!("[{label}] using pooled WebSocket connection"));
        stats.ws.fetch_add(1, Ordering::Relaxed);
        cooldown.clear_ip(&target_ip);
        cooldown.clear_dc(requested_dc, parsed.is_media);
        return bridge_websocket(
            clt_read, clt_write, ws, relay_init, crypto, parsed.proto_tag,
            stats, logger, label,
        )
        .await;
    }

    // #2 — прямое подключение с различением типа ошибки
    logger.log(format!(
        "[{label}] connecting to Telegram WS via {target_ip}:443; candidates={domains:?}"
    ));

    let tls = match make_tls_connector() {
        Ok(t) => t,
        Err(e) => return Err(e.into()),
    };

    let mut all_redirect = true;
    let mut ws_result: Option<WsStream> = None;
    let mut got_timeout = false;

    for domain in &domains {
        match connect_ws_typed(&target_ip, domain, &tls).await {
            Ok(ws) => {
                all_redirect = false;
                ws_result = Some(ws);
                break;
            }
            Err(WsConnectError::Redirect) => {
                stats.ws_errors.fetch_add(1, Ordering::Relaxed);
                logger.log(format!("[{label}] WS got redirect from {domain}"));
                // all_redirect остаётся true
            }
            Err(WsConnectError::Timeout) => {
                stats.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirect = false;
                got_timeout = true;
                logger.log(format!("[{label}] WS timeout from {domain}"));
                break;
            }
            Err(WsConnectError::Other(err)) => {
                stats.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirect = false;
                logger.log(format!("[{label}] WS error from {domain}: {err}"));
            }
        }
    }

    if let Some(ws) = ws_result {
        // Успех — снимаем cooldown, сбрасываем blacklist для этого DC
        cooldown.clear_ip(&target_ip);
        cooldown.clear_dc(requested_dc, parsed.is_media);
        logger.log(format!("[{label}] direct WebSocket connected"));
        stats.ws.fetch_add(1, Ordering::Relaxed);
        return bridge_websocket(
            clt_read, clt_write, ws, relay_init, crypto, parsed.proto_tag,
            stats, logger, label,
        )
        .await;
    }

    // #1 — запомнить cooldown при таймауте
    if got_timeout {
        cooldown.mark_ip_failed(&target_ip);
        logger.log(format!(
            "[{label}] WS connect to {target_ip} timed out, cooldown {}s",
            IP_FAIL_COOLDOWN.as_secs()
        ));
    } else {
        cooldown.mark_dc_failed(requested_dc, parsed.is_media);
    }

    // #2 — если все домены дали redirect → blacklist
    if all_redirect && !domains.is_empty() {
        blacklist.blacklist(requested_dc, parsed.is_media);
        logger.log(format!(
            "[{label}] DC{requested_dc} blacklisted for WS (all 302 redirects)"
        ));
    }

    logger.log(format!("[{label}] direct WebSocket failed; using fallback"));
    bridge_fallback(
        clt_read, clt_write, &target_ip, requested_dc, is_test_dc,
        relay_init, crypto, parsed.proto_tag,
        config, stats, logger, label, cf_domains, cf_worker_pool,
        dc_balancer,
    )
    .await
}

// ============================================================
// PROXY protocol / client init
// ============================================================

async fn read_proxy_protocol(
    stream: &mut TcpStream,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut line = Vec::with_capacity(108);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") || line.len() >= 108 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&line);
    if !text.starts_with("PROXY ") {
        return Ok(None);
    }
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() >= 6 {
        Ok(Some(format!("{}:{}", parts[2], parts[4])))
    } else {
        Ok(None)
    }
}

async fn read_client_init(
    mut stream: TcpStream,
    secret: &[u8],
    config: &Config,
    label: &str,
    stats: &Stats,
    logger: &AppLogger,
) -> Result<Option<([u8; HANDSHAKE_LEN], BoxRead, BoxWrite)>, Box<dyn std::error::Error>> {
    let mut first = [0u8; 1];
    if tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut first))
        .await
        .is_err()
    {
        logger.log(format!(
            "[{label}] timeout or error while waiting for the first client byte"
        ));
        return Ok(None);
    }
    logger.log(format!(
        "[{label}] first client byte received: 0x{:02X}",
        first[0]
    ));

    if !config.fake_tls_domain.is_empty() && first[0] == TLS_RECORD_HANDSHAKE {
        logger.log(format!("[{label}] Fake TLS ClientHello detected"));
        let mut hdr_rest = [0u8; 4];
        if stream.read_exact(&mut hdr_rest).await.is_err() {
            logger.log(format!("[{label}] Fake TLS header read failed"));
            return Ok(None);
        }
        let rec_len = u16::from_be_bytes([hdr_rest[2], hdr_rest[3]]) as usize;
        let mut record_body = vec![0u8; rec_len];
        if stream.read_exact(&mut record_body).await.is_err() {
            logger.log(format!(
                "[{label}] Fake TLS body read failed: expected {rec_len} bytes"
            ));
            return Ok(None);
        }

        let mut client_hello = Vec::with_capacity(5 + rec_len);
        client_hello.push(first[0]);
        client_hello.extend_from_slice(&hdr_rest);
        client_hello.extend_from_slice(&record_body);

        let Some((client_random, session_id, _timestamp)) =
            verify_client_hello(&client_hello, secret)
        else {
            logger.log(format!(
                "[{label}] Fake TLS verification failed; masking to {}",
                config.fake_tls_domain
            ));
            proxy_to_masking_domain(stream, client_hello, &config.fake_tls_domain, stats).await?;
            return Ok(None);
        };

        let server_hello = build_server_hello(secret, &client_random, &session_id);
        stream.write_all(&server_hello).await?;
        logger.log(format!(
            "[{label}] Fake TLS verified; ServerHello sent: {} bytes",
            server_hello.len()
        ));

        let (mut plain_read, plain_write) = fake_tls_transport(stream);
        let mut handshake = [0u8; HANDSHAKE_LEN];
        plain_read.read_exact(&mut handshake).await?;
        return Ok(Some((
            handshake,
            Box::new(plain_read),
            Box::new(plain_write),
        )));
    }

    if !config.fake_tls_domain.is_empty() {
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            config.fake_tls_domain
        );
        stream.write_all(redirect.as_bytes()).await?;
        logger.log(format!(
            "[{label}] non-TLS request redirected to {}",
            config.fake_tls_domain
        ));
        return Ok(None);
    }

    let mut handshake = [0u8; HANDSHAKE_LEN];
    handshake[0] = first[0];
    if tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_exact(&mut handshake[1..]),
    )
    .await
    .is_err()
    {
        logger.log(format!(
            "[{label}] timeout or error while reading the remaining 63 handshake bytes"
        ));
        return Ok(None);
    }
    logger.log(format!(
        "[{label}] raw MTProto handshake received: 64 bytes"
    ));
    let (read, write) = stream.into_split();
    Ok(Some((handshake, Box::new(read), Box::new(write))))
}

// ============================================================
// Fake TLS
// ============================================================

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    if data.len() < 43 || data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }

    let client_random = data[11..43].to_vec();
    let mut zeroed = data.to_vec();
    zeroed[11..43].fill(0);

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28] != client_random[..28] {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.abs_diff(timestamp as u64) > TIMESTAMP_TOLERANCE {
        return None;
    }

    let session_id = if data.len() >= 76 && data[43] == 0x20 {
        data[44..76].to_vec()
    } else {
        vec![0u8; 32]
    };

    Some((client_random, session_id, timestamp))
}

fn build_server_hello(secret: &[u8], client_random: &[u8], session_id: &[u8]) -> Vec<u8> {
    let mut sh = vec![
        0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03,
    ];
    sh.extend_from_slice(&[0u8; 32]);
    sh.push(0x20);
    sh.extend_from_slice(&session_id[..32]);
    sh.extend_from_slice(&[
        0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    ]);
    let mut pubkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut pubkey);
    sh.extend_from_slice(&pubkey);
    sh.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

    let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    let encrypted_size = 1900 + (rand::thread_rng().next_u32() as usize % 201);
    let mut encrypted_data = vec![0u8; encrypted_size];
    rand::thread_rng().fill_bytes(&mut encrypted_data);

    let mut response = sh;
    response.extend_from_slice(&ccs);
    response.extend_from_slice(&[0x17, 0x03, 0x03]);
    response.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    response.extend_from_slice(&encrypted_data);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();
    response[11..43].copy_from_slice(&server_random);
    response
}

fn fake_tls_transport(stream: TcpStream) -> (ReadHalf<DuplexStream>, WriteHalf<DuplexStream>) {
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let (plain_in_write_side, plain_in_read_side) = tokio::io::duplex(128 * 1024);
    let (plain_out_write_side, mut plain_out_read_side) = tokio::io::duplex(128 * 1024);
    let (plain_read, plain_in_write) = tokio::io::split(plain_in_read_side);
    let (plain_out_unused_read, plain_write) = tokio::io::split(plain_out_write_side);

    tokio::spawn(async move {
        let mut write_side = plain_in_write_side;
        loop {
            let mut hdr = [0u8; 5];
            if tcp_read.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let rtype = hdr[0];
            let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if rtype == TLS_RECORD_CCS {
                let mut skip = vec![0u8; rec_len];
                if tcp_read.read_exact(&mut skip).await.is_err() {
                    break;
                }
                continue;
            }
            if rtype != TLS_RECORD_APPDATA {
                break;
            }
            let mut payload = vec![0u8; rec_len];
            if tcp_read.read_exact(&mut payload).await.is_err() {
                break;
            }
            if write_side.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 16_384];
        loop {
            match plain_out_read_side.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let records = wrap_tls_records(&buf[..n]);
                    if tcp_write.write_all(&records).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    drop(plain_in_write);
    drop(plain_out_unused_read);
    (plain_read, plain_write)
}

fn wrap_tls_records(data: &[u8]) -> Vec<u8> {
    let mut records = Vec::with_capacity(data.len() + 5);
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        records.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
        records.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        records.extend_from_slice(chunk);
    }
    records
}

async fn proxy_to_masking_domain(
    mut client: TcpStream,
    initial_data: Vec<u8>,
    domain: &str,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut upstream = TcpStream::connect(format!("{domain}:443")).await?;
    stats.masked.fetch_add(1, Ordering::Relaxed);
    if !initial_data.is_empty() {
        upstream.write_all(&initial_data).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

// ============================================================
// Handshake / crypto
// ============================================================

struct ParsedHandshake {
    dc: i16,
    is_media: bool,
    proto_tag: [u8; 4],
}

fn parse_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<ParsedHandshake> {
    let dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hasher = Sha256::new();
    hasher.update(dec_prekey);
    hasher.update(secret);
    let dec_key = hasher.finalize();
    let mut decryptor = Aes256Ctr::new(&dec_key.into(), dec_iv.into());
    let mut decrypted = *handshake;
    decryptor.apply_keystream(&mut decrypted);

    let proto_tag: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]
        .try_into()
        .ok()?;
    let proto = u32::from_be_bytes(proto_tag);
    if proto != PROTO_ABRIDGED && proto != PROTO_INTERMEDIATE && proto != PROTO_PADDED_INTERMEDIATE
    {
        return None;
    }

    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);
    let dc = dc_idx.abs();
    if dc == 0 {
        return None;
    }

    Some(ParsedHandshake {
        dc,
        is_media: dc_idx < 0,
        proto_tag,
    })
}

fn generate_relay_init(proto_tag: [u8; 4], dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let mut relay_init = [0u8; HANDSHAKE_LEN];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == 0xef {
            continue;
        }
        if matches!(
            &relay_init[0..4],
            b"HEAD"
                | b"POST"
                | b"GET "
                | b"OPTI"
                | b"\xee\xee\xee\xee"
                | b"\xdd\xdd\xdd\xdd"
                | b"\x16\x03\x01\x02"
        ) {
            continue;
        }
        if &relay_init[4..8] == b"\x00\x00\x00\x00" {
            continue;
        }
        break;
    }

    let r_enc_key = relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN].to_vec();
    let r_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].to_vec();
    let mut init_encryptor =
        Aes256Ctr::new(r_enc_key.as_slice().into(), r_enc_iv.as_slice().into());
    let mut enc_full = relay_init;
    init_encryptor.apply_keystream(&mut enc_full);

    let mut tail = BytesMut::with_capacity(8);
    tail.put_slice(&proto_tag);
    tail.put_i16_le(dc_idx);
    let mut random_tail = [0u8; 2];
    rand::thread_rng().fill_bytes(&mut random_tail);
    tail.put_slice(&random_tail);

    for i in 0..8 {
        relay_init[PROTO_TAG_POS + i] =
            tail[i] ^ (enc_full[PROTO_TAG_POS + i] ^ relay_init[PROTO_TAG_POS + i]);
    }

    relay_init
}

struct CryptoCtx {
    clt_decryptor: Aes256Ctr,
    clt_encryptor: Aes256Ctr,
    tg_encryptor: Aes256Ctr,
    tg_decryptor: Aes256Ctr,
}

fn build_crypto(
    handshake: &[u8; HANDSHAKE_LEN],
    secret: &[u8],
    relay_init: &[u8; HANDSHAKE_LEN],
) -> CryptoCtx {
    let dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut dec_hasher = Sha256::new();
    dec_hasher.update(dec_prekey);
    dec_hasher.update(secret);
    let clt_dec_key = dec_hasher.finalize();
    let mut clt_decryptor = Aes256Ctr::new(&clt_dec_key.into(), dec_iv.into());
    let mut dummy = [0u8; HANDSHAKE_LEN];
    clt_decryptor.apply_keystream(&mut dummy);

    let mut clt_enc_piv = [0u8; PREKEY_LEN + IV_LEN];
    clt_enc_piv.copy_from_slice(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    clt_enc_piv.reverse();
    let mut enc_hasher = Sha256::new();
    enc_hasher.update(&clt_enc_piv[..PREKEY_LEN]);
    enc_hasher.update(secret);
    let clt_enc_key = enc_hasher.finalize();
    let clt_encryptor = Aes256Ctr::new(&clt_enc_key.into(), (&clt_enc_piv[PREKEY_LEN..]).into());

    let r_enc_key = relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN].to_vec();
    let r_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].to_vec();
    let mut tg_encryptor =
        Aes256Ctr::new(r_enc_key.as_slice().into(), r_enc_iv.as_slice().into());
    let mut dummy = [0u8; HANDSHAKE_LEN];
    tg_encryptor.apply_keystream(&mut dummy);

    let mut r_dec_pi = [0u8; PREKEY_LEN + IV_LEN];
    r_dec_pi.copy_from_slice(&relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    r_dec_pi.reverse();
    let tg_decryptor = Aes256Ctr::new(
        (&r_dec_pi[..PREKEY_LEN]).into(),
        (&r_dec_pi[PREKEY_LEN..]).into(),
    );

    CryptoCtx {
        clt_decryptor,
        clt_encryptor,
        tg_encryptor,
        tg_decryptor,
    }
}

// ============================================================
// bridge_websocket — #4 send_batch через SinkExt::feed
// ============================================================

async fn bridge_websocket(
    mut clt_read: BoxRead,
    mut clt_write: BoxWrite,
    ws_stream: WsStream,
    relay_init: [u8; HANDSHAKE_LEN],
    crypto: CryptoCtx,
    proto_tag: [u8; 4],
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    logger.log(format!("[{label}] WS bridge started"));
    let (ws_write, mut ws_read) = ws_stream.split();
    let ws_write = Arc::new(tokio::sync::Mutex::new(ws_write));
    if let Err(err) = ws_write
        .lock()
        .await
        .send(Message::Binary(relay_init.to_vec()))
        .await
    {
        logger.log(format!("[{label}] WS relay-init write failed: {err}"));
        return Err(err.into());
    }
    logger.log(format!("[{label}] WS relay-init sent: 64 bytes"));

    let mut clt_decryptor = crypto.clt_decryptor;
    let mut tg_encryptor = crypto.tg_encryptor;
    let mut splitter = FastSplitter::new(&proto_tag);
    let up_ws_write = ws_write.clone();
    let up_stats = stats.clone();
    let up_logger = logger.clone();
    let up_label = label.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        loop {
            match clt_read.read(&mut buf).await {
                Ok(0) => {
                    up_logger.log(format!(
                        "[{up_label}] client -> WS EOF after {chunks} chunks / {bytes} bytes"
                    ));
                    if let Some(tail) = splitter.flush() {
                        let tail_len = tail.len();
                        match up_ws_write
                            .lock()
                            .await
                            .send(Message::Binary(tail))
                            .await
                        {
                            Ok(()) => up_logger.log(format!(
                                "[{up_label}] client -> WS flushed tail: {tail_len} bytes"
                            )),
                            Err(err) => up_logger.log(format!(
                                "[{up_label}] client -> WS tail write failed: {err}"
                            )),
                        }
                    }
                    break;
                }
                Err(err) => {
                    up_logger.log(format!("[{up_label}] client -> WS read failed: {err}"));
                    break;
                }
                Ok(n) => {
                    chunks += 1;
                    bytes += n as u64;
                    up_stats.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    up_logger.trace(format!(
                        "[{up_label}] client -> WS read chunk #{chunks}: {n} encrypted bytes"
                    ));
                    let mut plain = buf[..n].to_vec();
                    clt_decryptor.apply_keystream(&mut plain);
                    let mut chunk = plain.clone();
                    tg_encryptor.apply_keystream(&mut chunk);

                    // #5 O(N) split + #4 send_batch
                    let parts = splitter.split(&plain, &chunk);
                    if parts.is_empty() {
                        continue;
                    }
                    let mut lock = up_ws_write.lock().await;
                    if parts.len() == 1 {
                        let part_len = parts[0].len();
                        if lock.send(Message::Binary(parts.into_iter().next().unwrap())).await.is_err() {
                            up_logger.log(format!(
                                "[{up_label}] client -> WS write failed for {part_len} bytes"
                            ));
                            return;
                        }
                        up_logger.trace(format!(
                            "[{up_label}] client -> WS sent binary frame: {part_len} bytes"
                        ));
                    } else {
                        // #4 — feed все части, один flush
                        let total: usize = parts.iter().map(|p| p.len()).sum();
                        let count = parts.len();
                        for part in parts {
                            if lock.feed(Message::Binary(part)).await.is_err() {
                                up_logger.log(format!(
                                    "[{up_label}] client -> WS batch feed failed"
                                ));
                                return;
                            }
                        }
                        if lock.flush().await.is_err() {
                            up_logger.log(format!(
                                "[{up_label}] client -> WS batch flush failed"
                            ));
                            return;
                        }
                        up_logger.trace(format!(
                            "[{up_label}] client -> WS batch: {count} frames / {total} bytes"
                        ));
                    }
                }
            }
        }
        up_logger.log(format!("[{up_label}] client -> WS task stopped"));
    });

    let mut tg_decryptor = crypto.tg_decryptor;
    let mut clt_encryptor = crypto.clt_encryptor;
    let down_ws_write = ws_write.clone();
    let down_stats = stats.clone();
    let down_logger = logger.clone();
    let down_label = label.clone();
    let mut down = tokio::spawn(async move {
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        while let Some(message) = ws_read.next().await {
            match message {
                Ok(Message::Binary(mut data)) => {
                    chunks += 1;
                    bytes += data.len() as u64;
                    down_logger.trace(format!(
                        "[{down_label}] WS -> client received binary frame #{chunks}: {} bytes",
                        data.len()
                    ));
                    down_stats
                        .bytes_down
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    tg_decryptor.apply_keystream(&mut data);
                    clt_encryptor.apply_keystream(&mut data);
                    if let Err(err) = clt_write.write_all(&data).await {
                        down_logger.log(format!(
                            "[{down_label}] WS -> client write failed: {err}"
                        ));
                        break;
                    }
                    down_logger.trace(format!(
                        "[{down_label}] WS -> client wrote {} encrypted bytes",
                        data.len()
                    ));
                }
                Ok(Message::Ping(payload)) => {
                    down_logger.trace(format!(
                        "[{down_label}] WS ping received: {} bytes",
                        payload.len()
                    ));
                    if let Err(err) = down_ws_write
                        .lock()
                        .await
                        .send(Message::Pong(payload))
                        .await
                    {
                        down_logger.log(format!(
                            "[{down_label}] WS pong write failed: {err}"
                        ));
                        break;
                    }
                }
                Ok(Message::Pong(payload)) => down_logger.trace(format!(
                    "[{down_label}] WS pong received: {} bytes",
                    payload.len()
                )),
                Ok(Message::Close(frame)) => {
                    down_logger.log(format!(
                        "[{down_label}] WS close received: {frame:?}"
                    ));
                    if let Err(err) = down_ws_write
                        .lock()
                        .await
                        .send(Message::Close(frame))
                        .await
                    {
                        down_logger.log(format!(
                            "[{down_label}] WS close acknowledgement failed: {err}"
                        ));
                    }
                    break;
                }
                Ok(_) => down_logger.trace(format!(
                    "[{down_label}] WS non-binary frame received"
                )),
                Err(err) => {
                    down_logger.log(format!(
                        "[{down_label}] WS receive failed: {err}"
                    ));
                    break;
                }
            }
        }
        down_logger.log(format!(
            "[{down_label}] WS -> client task stopped after {chunks} frames / {bytes} bytes"
        ));
    });

    tokio::select! {
        _ = &mut up => {
            logger.log(format!("[{label}] WS bridge ended: client->WS done; aborting reverse"));
            down.abort();
        },
        _ = &mut down => {
            logger.log(format!("[{label}] WS bridge ended: WS->client done; aborting forward"));
            up.abort();
        },
    }
    Ok(())
}

// ============================================================
// bridge_fallback — с CF Worker Pool (#6)
// ============================================================

#[allow(clippy::too_many_arguments)]
async fn bridge_fallback(
    clt_read: BoxRead,
    clt_write: BoxWrite,
    target_ip: &str,
    dc: i16,
    is_test_dc: bool,
    relay_init: [u8; HANDSHAKE_LEN],
    crypto: CryptoCtx,
    proto_tag: [u8; 4],
    config: Arc<Config>,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    label: String,
    cf_domains: CfDomains,
    cf_worker_pool: Arc<CfWorkerPool>,
    dc_balancer: Arc<DcBalancer>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. CF Worker — только для не-test DC
    if !is_test_dc && !config.cfproxy_worker_domains.is_empty() {
        // #6 — попробовать из пула
        if let Some((ws, worker_domain)) = cf_worker_pool.get(dc, &stats).await {
            logger.log(format!(
                "fallback: CF worker pool hit via {worker_domain} for DC{dc}"
            ));
            stats.cf_proxy.fetch_add(1, Ordering::Relaxed);
            stats.ws.fetch_add(1, Ordering::Relaxed);
            return bridge_websocket(
                clt_read, clt_write, ws, relay_init, crypto, proto_tag, stats, logger, label,
            )
            .await;
        }

        for worker_domain in &config.cfproxy_worker_domains {
            logger.log(format!(
                "fallback: trying Cloudflare Worker {worker_domain} for DC{dc}"
            ));
            match connect_ws_worker(worker_domain, dc, target_ip).await {
                Ok(ws) => {
                    logger.log(format!(
                        "fallback: Cloudflare Worker {worker_domain} connected"
                    ));
                    stats.cf_proxy.fetch_add(1, Ordering::Relaxed);
                    stats.ws.fetch_add(1, Ordering::Relaxed);
                    // #6 — заполнить пул на будущее (асинхронно)
                    {
                        let pool_clone = cf_worker_pool.clone();
                        let domain_clone = worker_domain.clone();
                        let target_clone = target_ip.to_string();
                        let dc_clone = dc;
                        tokio::spawn(async move {
                            if let Ok(ws2) =
                                connect_ws_worker(&domain_clone, dc_clone, &target_clone).await
                            {
                                pool_clone.push(dc_clone, ws2, domain_clone).await;
                            }
                        });
                    }
                    return bridge_websocket(
                        clt_read, clt_write, ws, relay_init, crypto, proto_tag,
                        stats, logger, label,
                    )
                    .await;
                }
                Err(err) => {
                    logger.log(format!(
                        "fallback: Cloudflare Worker {worker_domain} failed: {err}"
                    ));
                }
            }
        }
    }

    // 2. CF Proxy — только для не-test DC
    if !is_test_dc && config.fallback_cfproxy {
        let domains = cfproxy_domains(&config, dc, &cf_domains, &dc_balancer);
        for domain in domains {
            logger.log(format!("fallback: trying Cloudflare proxy {domain}"));
            match connect_ws_any(&domain, std::slice::from_ref(&domain)).await {
                Ok(ws) => {
                    logger.log(format!("fallback: Cloudflare proxy {domain} connected"));
                    if let Some(base_domain) = domain.strip_prefix(&format!("kws{dc}.")) {
                        dc_balancer.set_dc_domain(dc, base_domain.to_string());
                        stats.set_best_domain(base_domain.to_string(), stats.best_ping_ms());
                    }
                    stats.cf_proxy.fetch_add(1, Ordering::Relaxed);
                    stats.ws.fetch_add(1, Ordering::Relaxed);
                    return bridge_websocket(
                        clt_read, clt_write, ws, relay_init, crypto, proto_tag,
                        stats, logger, label,
                    )
                    .await;
                }
                Err(err) => {
                    logger.log(format!("fallback: Cloudflare proxy {domain} failed: {err}"));
                }
            }
        }
    }

    // 3. Прямой TCP
    let tcp_target = if is_test_dc {
        default_test_dc_ip(dc).unwrap_or(target_ip)
    } else {
        default_dc_ip(dc).unwrap_or(target_ip)
    };
    stats.tcp_fallback.fetch_add(1, Ordering::Relaxed);
    logger.log(format!(
        "fallback: using direct TCP {tcp_target}:443 for DC{dc}"
    ));
    bridge_tcp_fallback(
        clt_read, clt_write, tcp_target, relay_init, crypto, stats, logger, label,
    )
    .await
}

// DC Balancer с привязкой доменов
fn cfproxy_domains(
    config: &Config,
    dc: i16,
    cf_domains: &CfDomains,
    dc_balancer: &DcBalancer,
) -> Vec<String> {
    if !config.cfproxy_domains.is_empty() {
        return config
            .cfproxy_domains
            .iter()
            .map(|domain| format!("kws{dc}.{domain}"))
            .collect();
    }
    let base: Vec<String> = cf_domains.lock().unwrap().clone();
    dc_balancer.get_domains_for_dc(dc, &base)
}

async fn connect_ws_worker(
    worker_domain: &str,
    dc: i16,
    fallback_dst: &str,
) -> Result<WsStream, String> {
    let tls = make_tls_connector()?;
    let tcp_stream = TcpStream::connect(format!("{worker_domain}:443"))
        .await
        .map_err(|e| e.to_string())?;
    set_tcp_options(&tcp_stream, None);
    let tls_stream = tls
        .connect(worker_domain, tcp_stream)
        .await
        .map_err(|e| e.to_string())?;

    let path = format!("/apiws?dst={}&dc={}", fallback_dst, dc);
    let ws_url = format!("wss://{worker_domain}{path}");
    let request = http::Request::builder()
        .uri(&ws_url)
        .header("Host", worker_domain)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", "binary")
        .body(())
        .map_err(|e| e.to_string())?;
    let (ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ws_stream)
}

// ============================================================
// TCP bridges
// ============================================================

async fn bridge_tcp_fallback(
    clt_read: BoxRead,
    clt_write: BoxWrite,
    target_ip: &str,
    relay_init: [u8; HANDSHAKE_LEN],
    crypto: CryptoCtx,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    logger.log(format!(
        "[{label}] TCP fallback bridge connecting to {target_ip}:443"
    ));
    let mut remote = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{target_ip}:443")),
    )
    .await??;
    logger.log(format!(
        "[{label}] TCP fallback connected to {target_ip}:443"
    ));
    set_tcp_options(&remote, None);
    remote.write_all(&relay_init).await?;
    logger.log(format!("[{label}] TCP fallback relay-init sent: 64 bytes"));
    let (remote_read, remote_write) = remote.into_split();
    bridge_tcp_reencrypt(
        clt_read,
        clt_write,
        remote_read,
        remote_write,
        crypto,
        stats,
        logger,
        label,
    )
    .await;
    Ok(())
}

async fn bridge_tcp_reencrypt<R1, W1, R2, W2>(
    mut clt_read: R1,
    mut clt_write: W1,
    mut remote_read: R2,
    mut remote_write: W2,
    crypto: CryptoCtx,
    stats: Arc<Stats>,
    logger: Arc<AppLogger>,
    label: String,
) where
    R1: AsyncRead + Unpin + Send + 'static,
    W1: AsyncWrite + Unpin + Send + 'static,
    R2: AsyncRead + Unpin + Send + 'static,
    W2: AsyncWrite + Unpin + Send + 'static,
{
    let mut clt_decryptor = crypto.clt_decryptor;
    let mut tg_encryptor = crypto.tg_encryptor;
    let up_stats = stats.clone();
    let up_logger = logger.clone();
    let up_label = label.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        loop {
            match clt_read.read(&mut buf).await {
                Ok(0) => {
                    up_logger.log(format!(
                        "[{up_label}] client -> TCP EOF after {chunks} chunks / {bytes} bytes"
                    ));
                    break;
                }
                Err(err) => {
                    up_logger.log(format!("[{up_label}] client -> TCP read failed: {err}"));
                    break;
                }
                Ok(n) => {
                    chunks += 1;
                    bytes += n as u64;
                    up_stats.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    up_logger.trace(format!(
                        "[{up_label}] client -> TCP read chunk #{chunks}: {n} encrypted bytes"
                    ));
                    let mut data = buf[..n].to_vec();
                    clt_decryptor.apply_keystream(&mut data);
                    tg_encryptor.apply_keystream(&mut data);
                    if let Err(err) = remote_write.write_all(&data).await {
                        up_logger.log(format!(
                            "[{up_label}] client -> TCP write failed: {err}"
                        ));
                        break;
                    }
                    up_logger.trace(format!("[{up_label}] client -> TCP wrote {n} bytes"));
                }
            }
        }
        up_logger.log(format!("[{up_label}] client -> TCP task stopped"));
    });

    let mut tg_decryptor = crypto.tg_decryptor;
    let mut clt_encryptor = crypto.clt_encryptor;
    let down_stats = stats.clone();
    let down_logger = logger.clone();
    let down_label = label.clone();
    let mut down = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut chunks = 0u64;
        let mut bytes = 0u64;
        loop {
            match remote_read.read(&mut buf).await {
                Ok(0) => {
                    down_logger.log(format!(
                        "[{down_label}] TCP -> client EOF after {chunks} chunks / {bytes} bytes"
                    ));
                    break;
                }
                Err(err) => {
                    down_logger.log(format!(
                        "[{down_label}] TCP -> client read failed: {err}"
                    ));
                    break;
                }
                Ok(n) => {
                    chunks += 1;
                    bytes += n as u64;
                    down_stats.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    down_logger.trace(format!(
                        "[{down_label}] TCP -> client read chunk #{chunks}: {n} bytes"
                    ));
                    let mut data = buf[..n].to_vec();
                    tg_decryptor.apply_keystream(&mut data);
                    clt_encryptor.apply_keystream(&mut data);
                    if let Err(err) = clt_write.write_all(&data).await {
                        down_logger.log(format!(
                            "[{down_label}] TCP -> client write failed: {err}"
                        ));
                        break;
                    }
                    down_logger.trace(format!(
                        "[{down_label}] TCP -> client wrote {n} encrypted bytes"
                    ));
                }
            }
        }
        down_logger.log(format!("[{down_label}] TCP -> client task stopped"));
    });

    tokio::select! {
        _ = &mut up => {
            logger.log(format!("[{label}] TCP bridge ended: client->TCP done; aborting reverse"));
            down.abort();
        },
        _ = &mut down => {
            logger.log(format!("[{label}] TCP bridge ended: TCP->client done; aborting forward"));
            up.abort();
        },
    }
}

fn default_dc_ip(dc: i16) -> Option<&'static str> {
    match dc {
        1 => Some("149.154.175.50"),
        2 => Some("149.154.167.51"),
        3 => Some("149.154.175.100"),
        4 => Some("149.154.167.91"),
        5 => Some("149.154.171.5"),
        203 => Some("91.105.192.100"),
        _ => None,
    }
}
