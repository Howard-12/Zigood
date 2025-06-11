const win32 = @import("zigwin32").everything;
const std = @import("std");

const print = std.debug.print;
const info = std.log.info;


pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("[*] Running aes encryption example...\n", .{});
    aesEncrypt();

    try stdout.print("[*] Running aes decryption example...\n", .{});
    aesDecrypt();
}



// === examples
fn aesEncrypt() void {
    var data = "this is the top secret!".*;

    var key: [32]u8 = undefined;
    aes.generateRandomByte(&key);
    aes.printHexData("key".*[0..], &key);

    var iv: [16]u8 = undefined;
    aes.generateRandomByte(&iv);
    aes.printHexData("iv".*[0..], &iv);

    var aes_data: aes.AES = .{
        .plain_text = &data[0],
        .plain_size = data.len,
        .cipher_text = null,
        .cipher_size = 0,
        .key = key,
        .iv = iv,
    };

    _ = aes.encrypt(&aes_data);

    aes.printHexData("ciper_text".*[0..], @as([*]u8, @ptrCast(aes_data.cipher_text.?))[0..aes_data.cipher_size]);

    defer _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, aes_data.cipher_text);
}

fn aesDecrypt() void {
    const key = [_]u8{
            0x2a, 0x21, 0x3e, 0x71, 0xaa, 0x73, 0x4e, 0x5a, 0x88, 0x69, 0x0c, 0x33, 0x46, 0x52, 0xe0, 0xaa,
            0xac, 0xa7, 0x1c, 0x97, 0x18, 0xe0, 0x4c, 0xa9, 0x83, 0x34, 0x2c, 0x18, 0xb5, 0x0a, 0xf7, 0xc6 };
    const iv = [_]u8{
            0xea, 0x1f, 0x08, 0xaa, 0xbc, 0x7e, 0x0b, 0x97, 0x20, 0x38, 0x7f, 0xf6, 0x5b, 0xa7, 0xd8, 0xc9 };
    const cipher_text = [_]u8{
            0x7c, 0x16, 0x07, 0x4d, 0x2b, 0xcb, 0x1f, 0xf7, 0x36, 0x02, 0x02, 0x42, 0x20, 0x96, 0xe9, 0x32,
            0x7c, 0xe0, 0x34, 0x61, 0xe8, 0xf0, 0x5a, 0xd5, 0xee, 0x56, 0x60, 0x2a, 0x14, 0x88, 0x2e, 0xa1
    };
    aes.printHexData("key".*[0..], @constCast(&key));
    aes.printHexData("iv".*[0..], @constCast(&iv));
    aes.printHexData("cipher_text".*[0..], @constCast(&cipher_text));

    const original_plain_sze = 23;
    var aes_data: aes.AES = .{
        .plain_text = null,
        .plain_size = 0,
        .cipher_text = &@constCast(&cipher_text)[0],
        .cipher_size = cipher_text.len,
        .key = key,
        .iv = iv,
    };

    _ = aes.decrypt(&aes_data, original_plain_sze);
    std.log.info("Decrypted: {s}", .{@as([*]u8, @ptrCast(aes_data.plain_text.?))[0..aes_data.plain_size]});
}


const aes = @import("encryption/aes.zig");


// === override std
pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = myLogFn,
};

pub fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const scope_prefix = "(" ++ switch (scope) {
        .my_project, .nice_library, std.log.default_log_scope => @tagName(scope),
        else => if (@intFromEnum(level) <= @intFromEnum(std.log.Level.err))
            @tagName(scope)
        else
            return,
    } ++ "): ";

    const prefix = "[" ++ comptime level.asText() ++ "] " ++ scope_prefix;

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}
