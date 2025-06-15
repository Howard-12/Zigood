const std = @import("std");

pub fn pad_to_blocksize(allocator: std.mem.Allocator, buf: []const u8, block_size: usize) ![]u8 {
    if (buf.len < block_size) {
        const result = try allocator.alloc(u8, block_size);

        @memcpy(result[0..buf.len], buf);
        @memset(result[buf.len..], @intCast(buf.len));

        return result;
    }

    const remainder = buf.len % block_size;
    if (remainder == 0)
        return try allocator.dupe(u8, buf);

    const result = try allocator.alloc(u8, buf.len + (block_size - remainder));

    @memcpy(result[0..buf.len], buf);
    @memset(result[buf.len..], @intCast(block_size - remainder));

    return result;
}

test "buffer is smaller than block size" {
    const allocator = std.testing.allocator;

    const s = [_]u8 {0x12, 0x21, 0x90};
    const padded_str = try pad_to_blocksize(allocator, &s, 5);
    defer allocator.free(padded_str);

    const expected = [_]u8{0x12, 0x21, 0x90, 0x3, 0x3};

    try std.testing.expectEqualStrings(&expected, padded_str);
}

test "buffer is equal to the block size" {
    const allocator = std.testing.allocator;

    const s = [_]u8 {0x12, 0x21, 0x90, 0x90, 0x90};
    const padded_str = try pad_to_blocksize(allocator, &s, 5);
    defer allocator.free(padded_str);

    const expected = [_]u8{0x12, 0x21, 0x90, 0x90, 0x90};

    try std.testing.expectEqualStrings(&expected, padded_str);
}

test "buffer is larger than the block size" {
    const allocator = std.testing.allocator;

    const s = [_]u8 {0x12, 0x21, 0x90, 0x90, 0x90, 0x90};
    const padded_str = try pad_to_blocksize(allocator, &s, 5);
    defer allocator.free(padded_str);

    const expected = [_]u8{0x12, 0x21, 0x90, 0x90, 0x90, 0x90, 0x4, 0x4, 0x4, 0x4};

    try std.testing.expectEqualStrings(&expected, padded_str);
}


