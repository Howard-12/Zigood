const win32 = @import("zigwin32").everything;
const print = @import("std").debug.print;

/// Encrypt the payload with a single byte as the key
pub fn xorByOneKey(shellcode: []u8, key: u8) void {
    for (shellcode) |*byte| {
        byte.* ^= key;
    }
}

/// Encrypt the payload with a single byte key and the index of the payload
pub fn xorByiKeys(shellcode: []u8, key: u8) void {
    for (shellcode, 0..shellcode.len) |*byte, i|{
        byte.* ^= (key + @as(u8, @intCast(i)));
    }
}

/// Encrypt the payload with a array of bytes as the key
pub fn xorByInputKey(shellcode: []u8, key: []const u8) void {
    for (shellcode, 0..) |*byte, i| {
        byte.* ^= (key[i % key.len]);
    }
}



const std = @import("std");
test "test xor encryption and decryption" {
    var shellcode_str = "This is very spooky stuff =)".*;
    const shellcode = shellcode_str[0..];

    const key = "\x00\x01\x02\x03\x04\x05";

    // encrypt
    xorByInputKey(shellcode, key);

    const expected = [_]u8{ 84, 105, 107, 112, 36, 108, 115, 33, 116, 102, 118, 124, 32, 114, 114, 108, 107, 110, 121, 33, 113, 119, 113, 99, 102, 33, 63, 42 };

    try std.testing.expectEqual(expected, shellcode.*);

    // decrypt
    xorByInputKey(shellcode, key);

    try std.testing.expectEqual(shellcode_str, shellcode.*);
}
