#![windows_subsystem = "windows"]

mod autostart;
mod clipboard;
mod proxy;
mod tray;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::windows::WindowExtWindows;
use tao::window::WindowBuilder;
use tokio::sync::watch;
use wry::WebViewBuilder;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, SetForegroundWindow, ShowWindow,
    MB_ICONINFORMATION, MB_OK, SW_RESTORE,
    WM_COMMAND, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP,
};

const WM_POWERBROADCAST: u32 = 0x0218;
const PBT_APMRESUMEAUTOMATIC: usize = 0x0012;
const PBT_APMRESUMESUSPEND: usize = 0x0007;
const PBT_APMSUSPEND: usize = 0x0004;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub sni: String,
    pub use_fake_tls: bool,
    pub logging: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: 1443,
            sni: "cloudflare.com".to_string(),
            use_fake_tls: true,
            logging: false,
        }
    }
}

fn get_config_path() -> PathBuf {
    if let Ok(mut exe) = env::current_exe() {
        exe.pop();
        exe.push("config.json");
        return exe;
    }
    PathBuf::from("config.json")
}

impl AppConfig {
    pub fn load() -> Self {
        let path = get_config_path();
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&content) {
                return cfg;
            }
        }
        let def = Self::default();
        def.save();
        def
    }

    pub fn save(&self) {
        let path = get_config_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

#[derive(Debug)]
enum CustomEvent {
    Tick,
    Ipc(String),
    RestoreWindow,
}

#[derive(serde::Deserialize)]
struct IpcMessage {
    cmd: String,
    port: Option<u16>,
    sni: Option<String>,
    use_fake_tls: Option<bool>,
    enabled: Option<bool>,
    url: Option<String>,
}

const ICON_DARK_BYTES: &[u8] = include_bytes!("../icon.ico");
const ICON_GREEN_BYTES: &[u8] = include_bytes!("../icon_active.ico");

fn setup_process_job_object() {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if !job.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let res = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if res != 0 {
                AssignProcessToJobObject(job, GetCurrentProcess());
            }
        }
    }
}

struct AppShared {
    hwnd: HWND,
    event_proxy: EventLoopProxy<CustomEvent>,
    is_running: Arc<AtomicBool>,
    balloon_shown: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    stats: Arc<proxy::Stats>,
    logger: Arc<proxy::AppLogger>,
    tokio_rt: Arc<tokio::runtime::Runtime>,
    port: Arc<Mutex<u16>>,
    sni: Arc<Mutex<String>>,
    use_fake_tls: Arc<AtomicBool>,
    tray: Arc<Mutex<Option<tray::TrayIcon>>>,
    hicon_dark: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
    hicon_green: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
}

impl AppShared {
    fn save_config(&self) {
        let p = *self.port.lock().unwrap();
        let s = self.sni.lock().unwrap().clone();
        let tls = self.use_fake_tls.load(Ordering::Relaxed);
        let log = self.logger.is_enabled();
        let cfg = AppConfig {
            port: p,
            sni: s,
            use_fake_tls: tls,
            logging: log,
        };
        cfg.save();
    }
}

static mut GLOBAL_SHARED: *mut AppShared = std::ptr::null_mut();

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn compute_proxy_link(port: u16, sni: &str, fake_tls: bool) -> String {
    let host = "127.0.0.1";
    let secret_hex = "aa6a5bc1c399a42ba92d4448e91df797";
    if fake_tls && !sni.is_empty() {
        format!(
            "tg://proxy?server={host}&port={port}&secret=ee{}{}",
            secret_hex,
            hex::encode(sni.as_bytes())
        )
    } else {
        format!("tg://proxy?server={host}&port={port}&secret=dd{secret_hex}")
    }
}

fn start_proxy_task(shared: &AppShared) {
    if shared.is_running.load(Ordering::SeqCst) {
        return;
    }

    let port = *shared.port.lock().unwrap();
    let sni = shared.sni.lock().unwrap().clone();
    let use_fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);

    let mut cfg = proxy::Config::default_gui();
    cfg.port = port;
    if use_fake_tls {
        cfg.fake_tls_domain = sni;
    } else {
        cfg.fake_tls_domain.clear();
    }

    let config = Arc::new(cfg);
    let stats = shared.stats.clone();
    let logger = shared.logger.clone();
    let _ = shared.shutdown_tx.send(false);
    let shutdown_rx = shared.shutdown_tx.subscribe();
    let is_running = shared.is_running.clone();

    is_running.store(true, Ordering::SeqCst);

    shared.tokio_rt.spawn(async move {
        let _ = proxy::run_proxy_server(config, stats, logger, shutdown_rx).await;
        is_running.store(false, Ordering::SeqCst);
    });

    if let Ok(guard) = shared.tray.lock() {
        if let Some(t) = guard.as_ref() {
            t.update_icon_and_tip(shared.hicon_green, &format!("Telegram Stealth Proxy (Активен, порт {port})"));
        }
    }
}

fn stop_proxy_task(shared: &AppShared) {
    if !shared.is_running.load(Ordering::SeqCst) {
        return;
    }

    let _ = shared.shutdown_tx.send(true);
    shared.is_running.store(false, Ordering::SeqCst);

    if let Ok(guard) = shared.tray.lock() {
        if let Some(t) = guard.as_ref() {
            t.update_icon_and_tip(shared.hicon_dark, "Telegram Stealth Proxy (Остановлен)");
        }
    }
}

// Win32 Subclass для перехвата WM_TRAYICON и команд меню трея
unsafe extern "system" fn window_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _ref_data: usize,
) -> LRESULT {
    let shared = match GLOBAL_SHARED.as_ref() {
        Some(s) => s,
        None => return DefSubclassProc(hwnd, msg, wparam, lparam),
    };

    match msg {
        tray::WM_TRAYICON => {
            let event = (lparam & 0xFFFF) as u32;
            match event {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                    let _ = shared.event_proxy.send_event(CustomEvent::RestoreWindow);
                }
                WM_RBUTTONUP => {
                    let is_running = shared.is_running.load(Ordering::Relaxed);
                    let is_autostart = autostart::is_autostart_enabled();
                    if let Ok(guard) = shared.tray.lock() {
                        if let Some(t) = guard.as_ref() {
                            t.show_context_menu(is_running, is_autostart);
                        }
                    }
                }
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            let cmd_id = (wparam & 0xFFFF) as usize;
            match cmd_id {
                tray::IDM_TRAY_SHOW => {
                    let _ = shared.event_proxy.send_event(CustomEvent::RestoreWindow);
                }
                tray::IDM_TRAY_START_STOP => {
                    if shared.is_running.load(Ordering::SeqCst) {
                        stop_proxy_task(shared);
                    } else {
                        let _ = shared.shutdown_tx.send(false);
                        start_proxy_task(shared);
                    }
                }
                tray::IDM_TRAY_COPY_LINK => {
                    let port = *shared.port.lock().unwrap();
                    let sni = shared.sni.lock().unwrap().clone();
                    let fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);
                    let link = compute_proxy_link(port, &sni, fake_tls);
                    if clipboard::copy_to_clipboard(hwnd, &link) {
                        let title = to_wide("Telegram Stealth Proxy");
                        let msg = to_wide("Ссылка прокси скопирована в буфер обмена!");
                        MessageBoxW(hwnd, msg.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION);
                    }
                }
                tray::IDM_TRAY_OPEN_TG => {
                    let port = *shared.port.lock().unwrap();
                    let sni = shared.sni.lock().unwrap().clone();
                    let fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);
                    let link = compute_proxy_link(port, &sni, fake_tls);
                    proxy::open_url(&link);
                }
                tray::IDM_TRAY_AUTOSTART => {
                    let cur = autostart::is_autostart_enabled();
                    let _ = autostart::set_autostart(!cur);
                }
                tray::IDM_TRAY_EXIT => {
                    if let Ok(guard) = shared.tray.lock() {
                        if let Some(t) = guard.as_ref() {
                            t.remove();
                        }
                    }
                    std::process::exit(0);
                }
                _ => {}
            }
            0
        }
        WM_POWERBROADCAST => {
            let event = wparam as usize;
            if event == PBT_APMRESUMEAUTOMATIC || event == PBT_APMRESUMESUSPEND {
                shared.logger.log("Windows wake-up detected (WM_POWERBROADCAST); recycling proxy connections".to_string());
                if shared.is_running.load(Ordering::SeqCst) {
                    stop_proxy_task(shared);
                    start_proxy_task(shared);
                }
            } else if event == PBT_APMSUSPEND {
                shared.logger.log("Windows sleep/suspend detected (WM_POWERBROADCAST)".to_string());
            }
            DefSubclassProc(hwnd, msg, wparam, lparam)
        }
        WM_DESTROY => {
            RemoveWindowSubclass(hwnd, Some(window_subclass_proc), 1);
            DefSubclassProc(hwnd, msg, wparam, lparam)
        }
        _ => DefSubclassProc(hwnd, msg, wparam, lparam),
    }
}

fn main() {
    setup_process_job_object();

    let args: Vec<String> = env::args().collect();
    let start_minimized = args.iter().any(|a| a == "--minimized" || a == "-m");

    let tokio_rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to initialize Tokio runtime"),
    );

    let app_cfg = AppConfig::load();
    let stats = Arc::new(proxy::Stats::new());
    let logger = Arc::new(
        proxy::AppLogger::new("proxy_gui.log", app_cfg.logging, false, 5.0, 1),
    );
    let (shutdown_tx, _) = watch::channel(false);

    let port = Arc::new(Mutex::new(app_cfg.port));
    let sni = Arc::new(Mutex::new(app_cfg.sni.clone()));
    let use_fake_tls = Arc::new(AtomicBool::new(app_cfg.use_fake_tls));

    let event_loop = EventLoopBuilder::<CustomEvent>::with_user_event().build();

    let window = WindowBuilder::new()
        .with_title("TG Stealth Proxy v1.0.0")
        .with_inner_size(LogicalSize::new(560.0, 580.0))
        .with_resizable(false)
        .with_visible(!start_minimized)
        .build(&event_loop)
        .expect("Failed to create window");

    let hwnd = window.hwnd() as HWND;

    // Включаем темный режим для заголовка окна Windows (DWM Immersive Dark Mode)
    unsafe {
        let dark_mode: i32 = 1;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &dark_mode as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }

    // Загрузка темной и зеленой иконок для трея
    let hicon_dark = tray::load_ico_from_bytes(ICON_DARK_BYTES, 32, 32);
    let hicon_green = tray::load_ico_from_bytes(ICON_GREEN_BYTES, 32, 32);

    let initial_icon = if !hicon_green.is_null() { hicon_green } else { hicon_dark };
    let tray_icon = tray::TrayIcon::new(hwnd, initial_icon);
    tray_icon.add("Telegram Stealth Proxy (Запуск...)");
    let tray_arc = Arc::new(Mutex::new(Some(tray_icon)));

    let shared = Box::new(AppShared {
        hwnd,
        event_proxy: event_loop.create_proxy(),
        is_running: Arc::new(AtomicBool::new(false)),
        balloon_shown: AtomicBool::new(false),
        shutdown_tx,
        stats: stats.clone(),
        logger,
        tokio_rt: tokio_rt.clone(),
        port: port.clone(),
        sni: sni.clone(),
        use_fake_tls: use_fake_tls.clone(),
        tray: tray_arc.clone(),
        hicon_dark,
        hicon_green,
    });

    unsafe {
        GLOBAL_SHARED = Box::into_raw(shared);
        SetWindowSubclass(hwnd, Some(window_subclass_proc), 1, 0);
    }

    // Запускаем прокси-сервер
    unsafe {
        start_proxy_task(&*GLOBAL_SHARED);
    }

    // Создаем WebView2
    let proxy_for_ipc = event_loop.create_proxy();
    let webview = WebViewBuilder::new()
        .with_html(include_str!("ui.html"))
        .with_ipc_handler(move |req| {
            let body = req.body().clone();
            let _ = proxy_for_ipc.send_event(CustomEvent::Ipc(body));
        })
        .build(&window)
        .expect("Failed to create webview");

    // Фоновый таймер раз в 1 сек для обновления UI
    let proxy_for_tick = event_loop.create_proxy();
    tokio_rt.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(1000));
        loop {
            interval.tick().await;
            let _ = proxy_for_tick.send_event(CustomEvent::Tick);
        }
    });

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(CustomEvent::RestoreWindow) => {
                window.set_visible(true);
                window.set_focus();
                unsafe {
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                }
                let _ = webview.focus();
            }
            Event::UserEvent(CustomEvent::Tick) => {
                let shared = unsafe { &*GLOBAL_SHARED };
                let is_running = shared.is_running.load(Ordering::Relaxed);
                let p = *shared.port.lock().unwrap();
                let s = shared.sni.lock().unwrap().clone();
                let fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);
                let link = compute_proxy_link(p, &s, fake_tls);

                let best_domain = shared.stats.best_domain();
                let best_ping_ms = shared.stats.best_ping_ms();
                let cf_route_info = if !best_domain.is_empty() {
                    best_domain
                } else {
                    "Cloudflare Anycast".to_string()
                };

                let state_json = serde_json::json!({
                    "is_running": is_running,
                    "active": shared.stats.active(),
                    "total": shared.stats.total(),
                    "traffic": proxy::human_bytes(shared.stats.bytes_up() + shared.stats.bytes_down()),
                    "bytes_up_str": proxy::human_bytes(shared.stats.bytes_up()),
                    "bytes_down_str": proxy::human_bytes(shared.stats.bytes_down()),
                    "errors": shared.stats.errors(),
                    "link": link,
                    "port": p,
                    "sni": s,
                    "use_fake_tls": fake_tls,
                    "is_autostart": autostart::is_autostart_enabled(),
                    "is_logging": shared.logger.is_enabled(),
                    "version": "1.0.0",
                    "cf_route_info": cf_route_info,
                    "best_ping_ms": best_ping_ms,
                });

                let script = format!("window.renderState({});", state_json);
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(CustomEvent::Ipc(msg_str)) => {
                if let Ok(msg) = serde_json::from_str::<IpcMessage>(&msg_str) {
                    let shared = unsafe { &*GLOBAL_SHARED };
                    match msg.cmd.as_str() {
                        "start" => {
                            let _ = shared.shutdown_tx.send(false);
                            start_proxy_task(shared);
                        }
                        "stop" => {
                            stop_proxy_task(shared);
                        }
                        "copy_link" => {
                            let p = *shared.port.lock().unwrap();
                            let s = shared.sni.lock().unwrap().clone();
                            let fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);
                            let link = compute_proxy_link(p, &s, fake_tls);
                            let _ = clipboard::copy_to_clipboard(shared.hwnd, &link);
                        }
                        "open_telegram" => {
                            let p = *shared.port.lock().unwrap();
                            let s = shared.sni.lock().unwrap().clone();
                            let fake_tls = shared.use_fake_tls.load(Ordering::Relaxed);
                            let link = compute_proxy_link(p, &s, fake_tls);
                            proxy::open_url(&link);
                        }
                        "open_url" => {
                            if let Some(url) = msg.url {
                                proxy::open_url(&url);
                            }
                        }
                        "set_autostart" => {
                            if let Some(en) = msg.enabled {
                                let _ = autostart::set_autostart(en);
                            }
                        }
                        "set_logging" => {
                            if let Some(en) = msg.enabled {
                                shared.logger.set_enabled(en);
                                shared.save_config();
                            }
                        }
                        "update_config" => {
                            if let Some(new_p) = msg.port {
                                *shared.port.lock().unwrap() = new_p;
                            }
                            if let Some(new_s) = msg.sni {
                                *shared.sni.lock().unwrap() = new_s;
                            }
                            if let Some(tls) = msg.use_fake_tls {
                                shared.use_fake_tls.store(tls, Ordering::Relaxed);
                            }
                            shared.save_config();
                        }
                        "minimize_to_tray" => {
                            window.set_visible(false);
                            if !shared.balloon_shown.swap(true, Ordering::SeqCst) {
                                if let Ok(guard) = shared.tray.lock() {
                                    if let Some(t) = guard.as_ref() {
                                        t.show_balloon("Stealth Proxy свернут", "Программа продолжает работать в системном трее.");
                                    }
                                }
                            }
                        }
                        "exit" => {
                            window.set_visible(false);
                            if let Ok(guard) = shared.tray.lock() {
                                if let Some(t) = guard.as_ref() {
                                    t.remove();
                                }
                            }
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                // При нажатии крестика скрываем окно в трей
                window.set_visible(false);
                let shared = unsafe { &*GLOBAL_SHARED };
                if !shared.balloon_shown.swap(true, Ordering::SeqCst) {
                    if let Ok(guard) = shared.tray.lock() {
                        if let Some(t) = guard.as_ref() {
                            t.show_balloon(
                                "Stealth Proxy свернут в трей",
                                "Программа работает в фоновом режиме. Чтобы выйти полностью, используйте меню в трее.",
                            );
                        }
                    }
                }
            }
            Event::LoopDestroyed => {
                let shared = unsafe { &*GLOBAL_SHARED };
                let _ = shared.shutdown_tx.send(true);
                if let Ok(guard) = shared.tray.lock() {
                    if let Some(t) = guard.as_ref() {
                        t.remove();
                    }
                }
                std::process::exit(0);
            }
            _ => {}
        }
    });
}
