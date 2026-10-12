use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconFromResourceEx, CreatePopupMenu, DestroyMenu, GetCursorPos,
    LookupIconIdFromDirectoryEx, SetForegroundWindow, TrackPopupMenu, HICON, LR_DEFAULTCOLOR,
    MF_CHECKED, MF_GRAYED, MF_SEPARATOR, MF_STRING, MF_UNCHECKED, TPM_BOTTOMALIGN,
    TPM_LEFTALIGN, TPM_RIGHTBUTTON,
};

pub fn load_ico_from_bytes(bytes: &[u8], width: i32, height: i32) -> HICON {
    unsafe {
        let offset = LookupIconIdFromDirectoryEx(
            bytes.as_ptr(),
            1, // TRUE = icon
            width,
            height,
            LR_DEFAULTCOLOR,
        );
        if offset > 0 {
            let res_bytes = &bytes[offset as usize..];
            CreateIconFromResourceEx(
                res_bytes.as_ptr(),
                res_bytes.len() as u32,
                1,
                0x00030000,
                width,
                height,
                LR_DEFAULTCOLOR,
            )
        } else {
            std::ptr::null_mut()
        }
    }
}

pub const WM_TRAYICON: u32 = 0x8000 + 101; // WM_USER + 101

pub const IDM_TRAY_SHOW: usize = 1001;
pub const IDM_TRAY_STATUS: usize = 1002;
pub const IDM_TRAY_START_STOP: usize = 1003;
pub const IDM_TRAY_COPY_LINK: usize = 1004;
pub const IDM_TRAY_OPEN_TG: usize = 1005;
pub const IDM_TRAY_AUTOSTART: usize = 1006;
pub const IDM_TRAY_EXIT: usize = 1007;

const TRAY_UID: u32 = 1;

fn str_to_wide_buf<const N: usize>(s: &str) -> [u16; N] {
    let mut buf = [0u16; N];
    let wide: Vec<u16> = OsStr::new(s).encode_wide().collect();
    let copy_len = wide.len().min(N - 1);
    buf[..copy_len].copy_from_slice(&wide[..copy_len]);
    buf
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub struct TrayIcon {
    hwnd: HWND,
    hicon: HICON,
}

impl TrayIcon {
    pub fn new(hwnd: HWND, hicon: HICON) -> Self {
        Self { hwnd, hicon }
    }

    pub fn add(&self, tip: &str) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = self.hicon;
        nid.szTip = str_to_wide_buf::<128>(tip);

        unsafe { Shell_NotifyIconW(NIM_ADD, &nid) != 0 }
    }

    #[allow(dead_code)]
    pub fn update_tip(&self, tip: &str) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_TIP;
        nid.szTip = str_to_wide_buf::<128>(tip);

        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 }
    }

    #[allow(dead_code)]
    pub fn update_icon(&self, hicon: HICON) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_ICON;
        nid.hIcon = hicon;

        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 }
    }

    pub fn update_icon_and_tip(&self, hicon: HICON, tip: &str) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_ICON | NIF_TIP;
        nid.hIcon = hicon;
        nid.szTip = str_to_wide_buf::<128>(tip);

        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 }
    }

    pub fn show_balloon(&self, title: &str, message: &str) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_INFO;
        nid.szInfoTitle = str_to_wide_buf::<64>(title);
        nid.szInfo = str_to_wide_buf::<256>(message);
        nid.dwInfoFlags = NIIF_INFO;

        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) != 0 }
    }

    pub fn remove(&self) -> bool {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = TRAY_UID;

        unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) != 0 }
    }

    pub fn show_context_menu(&self, is_running: bool, is_autostart: bool) {
        unsafe {
            let hmenu = CreatePopupMenu();
            if hmenu.is_null() {
                return;
            }

            let status_text = if is_running {
                to_wide_null("● Прокси: Работает")
            } else {
                to_wide_null("○ Прокси: Остановлен")
            };
            AppendMenuW(hmenu, MF_STRING | MF_GRAYED, IDM_TRAY_STATUS, status_text.as_ptr());

            let show_text = to_wide_null("Показать окно");
            AppendMenuW(hmenu, MF_STRING, IDM_TRAY_SHOW, show_text.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());

            let start_stop_text = if is_running {
                to_wide_null("⏹ Остановить прокси")
            } else {
                to_wide_null("▶ Запустить прокси")
            };
            AppendMenuW(hmenu, MF_STRING, IDM_TRAY_START_STOP, start_stop_text.as_ptr());

            let copy_text = to_wide_null("📋 Скопировать ссылку Telegram");
            AppendMenuW(hmenu, MF_STRING, IDM_TRAY_COPY_LINK, copy_text.as_ptr());

            let open_tg_text = to_wide_null("✈ Открыть в Telegram");
            AppendMenuW(hmenu, MF_STRING, IDM_TRAY_OPEN_TG, open_tg_text.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());

            let autostart_flags = if is_autostart { MF_CHECKED } else { MF_UNCHECKED };
            let autostart_text = to_wide_null("✔ Автозапуск с Windows");
            AppendMenuW(hmenu, MF_STRING | autostart_flags, IDM_TRAY_AUTOSTART, autostart_text.as_ptr());

            AppendMenuW(hmenu, MF_SEPARATOR, 0, ptr::null());

            let exit_text = to_wide_null("🚪 Выход");
            AppendMenuW(hmenu, MF_STRING, IDM_TRAY_EXIT, exit_text.as_ptr());

            let mut pt: POINT = std::mem::zeroed();
            GetCursorPos(&mut pt);

            SetForegroundWindow(self.hwnd);
            TrackPopupMenu(
                hmenu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                pt.x,
                pt.y,
                0,
                self.hwnd,
                ptr::null(),
            );

            DestroyMenu(hmenu);
        }
    }
}
