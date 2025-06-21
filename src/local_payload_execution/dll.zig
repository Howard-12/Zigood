const std = @import("std");
const win = std.os.windows;
const win32 = @import("zigwin32").everything;

pub fn DllMain(hinstDLL: win.HINSTANCE, fdwReason: win.DWORD, lpReserved: win.LPVOID) callconv(.winapi) win.BOOL {
    _ = hinstDLL;
    _ = lpReserved;
    switch (fdwReason) {
        win32.DLL_PROCESS_ATTACH => {},
        win32.DLL_PROCESS_DETACH => {},
        win32.DLL_THREAD_ATTACH => {},
        win32.DLL_THREAD_DETACH => {},
        else => {},
    }
    return win.TRUE;
}
