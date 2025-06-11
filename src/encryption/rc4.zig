const win32 = @import("zigwin32").everything;
const info = @import("std").log.info;
const std = @import("std");

pub const Rc4Context = struct {
    i: u8,
    j: u8,
    s: [256]u8,
};

///  init rc4
pub fn rc4Init(context: ?*Rc4Context, key: ?[]const u8) void {
    var j: u8 = undefined;
    var temp: u8 = undefined;

    // if ((context == null) || (key == null)) return;
    if (context == null) return;
    if (key == null) return;

    context.?.i = 0;
    context.?.j = 0;

    for (0..256) |index|
        context.?.s[index] = @as(u8, @intCast(index));

    for (0..256) |index| {
        j = (j +% context.?.s[index] +% key.?[index % key.?.len]);

        temp = context.?.s[index];
        context.?.s[index] = context.?.s[j];
        context.?.s[j] = temp;
    }
}

/// encrypt
pub fn rc4Cipher(context: ?*Rc4Context, input: []const u8, output: []u8) void {
    if (context == null) return;

    var temp: u8 = undefined;

    var length = output.len;

    var i: u8 = context.?.i;
    var j: u8 = context.?.j;
    var s: []u8 = &context.?.s;

    while (length > 0) : (length -= 1) {
        i = (i +% 1);
        j = (j +% s[i]);

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        output[length - 1] = input[length - 1] ^ s[s[i] +% s[j]];
    }

    context.?.i = i;
    context.?.j = j;
}


test "test rc41" {
    var shellcode_str = "This is verry spooky stuff, doing rc4 encryption !".*;
    const shellcode = shellcode_str[0..];
    var key_str = "\x00\x01\x02\x03\x04\x05".*;
    const key: []u8 = key_str[0..];

    // encrypt
    var rccontext: Rc4Context = .{
        .s = [_]u8{0} ** 256,
        .i =  0,
        .j = 0,
    };
    var ciphertext = [_]u8{0} ** shellcode_str.len;

    rc4Init(&rccontext, key);
    rc4Cipher(&rccontext, shellcode, &ciphertext);

    const expected = [_]u8{ 58, 127, 37, 146, 64, 211, 109, 190, 40, 81, 99, 8, 91, 12, 213, 68, 183, 91, 134, 63, 232, 59, 28, 116, 107, 7, 202, 191, 20, 80, 246, 30, 43, 146, 40, 66, 180, 118, 13, 175, 176, 136, 143, 184, 14, 117, 30, 182, 7, 138 };

    try std.testing.expectEqual(expected, ciphertext);


    // decrypt
    var drccontext: Rc4Context = .{
        .s = [_]u8{0} ** 256,
        .i =  0,
        .j = 0,
    };

    rc4Cipher(&drccontext, shellcode, &ciphertext);

    try std.testing.expectEqual(shellcode_str, ciphertext);
}
