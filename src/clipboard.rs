use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

const CF_UNICODETEXT: u32 = 13;

pub fn copy_to_clipboard(hwnd: HWND, text: &str) -> bool {
    let wide: Vec<u16> = OsStr::new(text).encode_wide().chain(Some(0)).collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return false;
        }

        EmptyClipboard();

        let h_mem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if h_mem.is_null() {
            CloseClipboard();
            return false;
        }

        let p_mem = GlobalLock(h_mem) as *mut u16;
        if p_mem.is_null() {
            CloseClipboard();
            return false;
        }

        ptr::copy_nonoverlapping(wide.as_ptr(), p_mem, wide.len());
        GlobalUnlock(h_mem);

        let res = SetClipboardData(CF_UNICODETEXT, h_mem as _);
        CloseClipboard();
        !res.is_null()
    }
}
