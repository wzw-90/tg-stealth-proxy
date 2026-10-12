use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ,
};

const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const APP_REG_NAME: &str = "TGStealthProxy";

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Проверяет, включен ли автозапуск в реестре
pub fn is_autostart_enabled() -> bool {
    unsafe {
        let subkey = to_wide(RUN_SUBKEY);
        let mut hkey: HKEY = ptr::null_mut();

        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        ) != ERROR_SUCCESS
        {
            return false;
        }

        let value_name = to_wide(APP_REG_NAME);
        let mut data_type: u32 = 0;
        let mut data_size: u32 = 0;

        let status = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            ptr::null_mut(),
            &mut data_size,
        );

        RegCloseKey(hkey);
        status == ERROR_SUCCESS && data_size > 0
    }
}

/// Включает или отключает автозапуск приложения при входе в Windows
pub fn set_autostart(enable: bool) -> Result<(), String> {
    unsafe {
        let subkey = to_wide(RUN_SUBKEY);
        let mut hkey: HKEY = ptr::null_mut();

        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );

        if status != ERROR_SUCCESS {
            return Err(format!("Не удалось открыть ветку реестра: код {status}"));
        }

        let value_name = to_wide(APP_REG_NAME);

        let res = if enable {
            // Получаем путь к текущему .exe и добавляем флаг --minimized
            let current_exe = env::current_exe().map_err(|e| e.to_string())?;
            let exe_cmd = format!("\"{}\" --minimized", current_exe.display());
            let wide_cmd = to_wide(&exe_cmd);
            let bytes_len = (wide_cmd.len() * 2) as u32;

            let set_status = RegSetValueExW(
                hkey,
                value_name.as_ptr(),
                0,
                REG_SZ,
                wide_cmd.as_ptr() as *const u8,
                bytes_len,
            );
            if set_status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(format!("Ошибка установки значения в реестр: {set_status}"))
            }
        } else {
            let del_status = RegDeleteValueW(hkey, value_name.as_ptr());
            if del_status == ERROR_SUCCESS || del_status == 2 {
                // 2 = ERROR_FILE_NOT_FOUND (уже удалено)
                Ok(())
            } else {
                Err(format!("Ошибка удаления значения из реестра: {del_status}"))
            }
        };

        RegCloseKey(hkey);
        res
    }
}
