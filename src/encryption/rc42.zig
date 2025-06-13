const win32 = @import("zigwin32").everything;
const NTSTATUS = @import("zigwin32").everything.NTSTATUS;
const winapi = @import("std").os.windows;
const std = @import("std");

/// USTRING struct
const USTRING = extern struct {
    /// Length of the buffer
    Length: winapi.DWORD,
    ///
    MaximumLength: winapi.DWORD,
    ///
    Buffer: winapi.PVOID,
};

const winapi_callconv= std.builtin.CallingConvention.winapi;
const fnsystemFunction032 = *const fn (data: *USTRING, key: *USTRING) callconv(winapi_callconv) NTSTATUS;

/// rc4 encrypt
pub fn rc4EncryptionViSystemFunc032(pRc4Key: []u8, pPayloadData: []u8, dwRc4KeySize: winapi.DWORD, sPayloadSize: winapi.DWORD) bool {
    const lib = "advapi32.dll";
    const func_name = "SystemFunction032";

    // get address of systemFunction032 from advapi32.dll
    const systemFunction032 = win32.GetProcAddress(win32.LoadLibraryA(lib), func_name);
    if (systemFunction032 == null) {
        print("[ERROR] can not load function: SystemFunction032\n", .{});
        return false;
    }

    // cast to function pointer
    const sysFun032 = @as(fnsystemFunction032, @ptrCast(systemFunction032.?));


    var key: USTRING = .{
        .Buffer = @as(*anyopaque, @ptrCast(pRc4Key)),
        .MaximumLength = dwRc4KeySize,
        .Length = dwRc4KeySize,
    };

    var data: USTRING = .{
        .Buffer = @as(*anyopaque, @ptrCast(pPayloadData)),
        .MaximumLength = sPayloadSize,
        .Length = sPayloadSize,
    };

    const status = sysFun032(&data, &key);
    if (status != 0) {
        std.log.err("SystemFunction032 FAILED with Error {}\n", .{status});
        return false;
    }

    return true;
}

const print = @import("std").debug.print;

test "test rc4 systemFunction032 encrypt/decrypt " {
    var shellcode_str = "This is very spooky stuff, doing rc4 encryption !".*;
    const shellcode = shellcode_str[0..];
    var key_str = "\x00\x01\x02\x03\x04\x05".*;
    const key: []u8 = key_str[0..];

    // encrypt
    _ = rc4EncryptionViSystemFunc032(key, shellcode, @as(u32, @intCast(key.len)), shellcode_str.len);
    // decrypt
    _ = rc4EncryptionViSystemFunc032(key, shellcode, @as(u32, @intCast(key.len)), shellcode_str.len);

    try std.testing.expectEqual(shellcode_str, shellcode.*);
}
