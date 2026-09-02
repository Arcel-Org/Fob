use crate::dto::UsbDeviceDto;

#[tauri::command(rename_all = "snake_case")]
pub fn list_devices() -> Vec<UsbDeviceDto> {
    fob_host::device::enumerate_usb_devices()
        .iter()
        .map(UsbDeviceDto::from)
        .collect()
}

/// Format the USB device at `path` as ExFAT, erasing all data. Destructive —
/// the frontend must confirm with the user before calling this.
#[tauri::command(rename_all = "snake_case")]
pub fn format_device(path: String) -> Result<(), String> {
    let dev = fob_host::device::enumerate_usb_devices()
        .into_iter()
        .find(|d| d.path.to_string_lossy() == path)
        .ok_or_else(|| "device not found — it may have been unplugged".to_string())?;
    fob_host::device::format_device(&dev).map_err(|e| e.to_string())
}
