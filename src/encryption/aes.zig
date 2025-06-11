const std = @import("std");
const winapi = @import("std").os.windows;
const win32 = @import("zigwin32").everything;

pub const AES = struct {
    plain_text: ?*u8,
    plain_size: u32,
    cipher_text: ?*u8,
    cipher_size: u32,
    key: [32]u8,
    iv: [16]u8,
};

fn nt_success(status: winapi.NTSTATUS) bool {
    return status == winapi.NTSTATUS.SUCCESS;
}

// TODO: with user selection random engine
pub fn generateRandomByte(byte: []u8) void {
    var r = std.Random.DefaultPrng.init(@as(u64, @bitCast(std.time.milliTimestamp())));
    r.fill(byte);
}

/// prints the input data as u8 array in zig
pub fn printHexData(name: []const u8, data: []u8) void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("const {s} = [_]u8{{", .{name}) catch {};
    for (data, 0..) |d, i| {
        if (i % 16 == 0) {
            stdout.print("\n\t", .{}) catch {};
        }
        if (i < data.len - 1) {
            stdout.print("0x{x:0>2}, ", .{d}) catch {};
        } else {
            stdout.print("0x{x:0>2} ", .{d}) catch {};
        }
    }
    stdout.print("}};\n", .{}) catch {};
}


/// Aes encryption
pub fn encrypt(aes: *AES) bool {
    var status: i32 = undefined;

    var algorithm: win32.BCRYPT_ALG_HANDLE = undefined;
    var keyhandle: win32.BCRYPT_ALG_HANDLE = undefined;

    var result: u32 = undefined;

    var key_object: ?*u8 = null;
    var key_object_size: u32 = 0;

    var cipher_text: ?*u8 = null;
    var cipher_text_size: u32 = 0;


    // === init aes algorithm handle ===
    status = win32.BCryptOpenAlgorithmProvider(
            &algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_AES_ALGORITHM),
            null,
            win32.BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS{}
    );

    defer _ = win32.BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptOpenAlgorithmProvider Faied: 0x{:>8}", .{status});
        return false;
    }

    // === get the size of the key object ===
    status = win32.BCryptGetProperty(
            algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_OBJECT_LENGTH),
            @ptrCast(&key_object_size),
            @sizeOf(u32),
            &result,
            0
    );
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGetProperty[1] Failed: 0x{:>8}", .{status});
        return false;
    }

    // === alloc memory for key object ===
    key_object = @ptrCast(win32.HeapAlloc(win32.GetProcessHeap(), win32.HEAP_NONE, key_object_size));
    defer _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, key_object);
    if (key_object == null) return false;

    // === set CBC mode ===
    status = win32.BCryptSetProperty(
            algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_CHAINING_MODE),
            @ptrCast(@constCast(std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_CHAIN_MODE_CBC))),
            win32.BCRYPT_CHAIN_MODE_CBC.len,
            0
    );
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGetProperty Failed: 0x{:>8}", .{status});
        return false;
    }

    // === generate key object ===
    status = win32.BCryptGenerateSymmetricKey(
            algorithm,
            &keyhandle,
            key_object,
            key_object_size,
            @ptrCast(&aes.key),
            32,
            0
    );
    defer _ = win32.BCryptDestroyKey(keyhandle);
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGenerateSymmetricKey Failed: 0x{:>8}", .{status});
        return false;
    }

    // === get size if the output buffer ===
    status = win32.BCryptEncrypt(
        keyhandle,
        @ptrCast(aes.plain_text),
        aes.plain_size,
        null,
        @ptrCast(&aes.iv),
        16,
        null,
        0,
        &cipher_text_size,
        @as(win32.NCRYPT_FLAGS, @bitCast(win32.BCRYPT_BLOCK_PADDING))
    );

    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptEncrypt[1] Failed: 0x{x:>8}", .{status});
        return false;
    }

    // === allocate for output ===
    cipher_text = @ptrCast(win32.HeapAlloc(
        win32.GetProcessHeap(),
        win32.HEAP_NONE,
        cipher_text_size
    ));
    if (cipher_text == null) return false;

    // === encrypt plain text ===
    status = win32.BCryptEncrypt(
        keyhandle,
        @ptrCast(aes.plain_text),
        aes.plain_size,
        null,
        @ptrCast(&aes.iv),
        16,
        cipher_text,
        cipher_text_size,
        &result,
        @as(win32.NCRYPT_FLAGS, @bitCast(win32.BCRYPT_BLOCK_PADDING))
    );

    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptEncrypt[2] Failed: 0x{:>8}", .{status});
        return false;
    }
    if (cipher_text == null) return false;

    aes.cipher_text = cipher_text;
    aes.cipher_size = cipher_text_size;

    return true;
}

/// Aes decryption
pub fn decrypt(aes: *AES, original_plain_size: u32) bool {
    var status: i32 = undefined;

    var algorithm: win32.BCRYPT_ALG_HANDLE = undefined;
    var keyhandle: win32.BCRYPT_ALG_HANDLE = undefined;

    var result: u32 = undefined;

    var key_object: ?*u8 = null;
    var key_object_size: u32 = 0;

    var plain_text: ?*u8 = null;
    var plain_text_size: u32 = 0;


    // === init aes algorithm handle ===
    status = win32.BCryptOpenAlgorithmProvider(
            &algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_AES_ALGORITHM),
            null,
            win32.BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS{}
    );

    defer _ = win32.BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptOpenAlgorithmProvider Faied: 0x{:>8}", .{status});
        return false;
    }

    // === get the size of the key object ===
    status = win32.BCryptGetProperty(
            algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_OBJECT_LENGTH),
            @ptrCast(&key_object_size),
            @sizeOf(u32),
            &result,
            0
    );
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGetProperty[1] Failed: 0x{:>8}", .{status});
        return false;
    }

    // === alloc memory for key object ===
    key_object = @ptrCast(win32.HeapAlloc(win32.GetProcessHeap(), win32.HEAP_NONE, key_object_size));
    defer _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, key_object);
    if (key_object == null) return false;

    // === set CBC mode ===
    status = win32.BCryptSetProperty(
            algorithm,
            std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_CHAINING_MODE),
            @ptrCast(@constCast(std.unicode.utf8ToUtf16LeStringLiteral(win32.BCRYPT_CHAIN_MODE_CBC))),
            win32.BCRYPT_CHAIN_MODE_CBC.len,
            0
    );
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGetProperty Failed: 0x{:>8}", .{status});
        return false;
    }

    // === generate key object ===
    status = win32.BCryptGenerateSymmetricKey(
            algorithm,
            &keyhandle,
            key_object,
            key_object_size,
            @ptrCast(&aes.key),
            32,
            0
    );
    defer _ = win32.BCryptDestroyKey(keyhandle);
    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptGenerateSymmetricKey Failed: 0x{:>8}", .{status});
        return false;
    }

    // === get size if the output buffer ===
    status = win32.BCryptDecrypt(
        keyhandle,
        @ptrCast(aes.cipher_text),
        aes.cipher_size,
        null,
        @ptrCast(&aes.iv),
        16,
        null,
        0,
        &plain_text_size,
        @as(win32.NCRYPT_FLAGS, @bitCast(win32.BCRYPT_BLOCK_PADDING))
    );

    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptEncrypt[1] Failed: 0x{x:>8}", .{status});
        return false;
    }

    // === allocate for output ===
    plain_text = @ptrCast(win32.HeapAlloc(
        win32.GetProcessHeap(),
        win32.HEAP_NONE,
        plain_text_size,
    ));
    if (plain_text == null) return false;

    // === encrypt plain text ===
    status = win32.BCryptDecrypt(
        keyhandle,
        @ptrCast(aes.cipher_text),
        aes.cipher_size,
        null,
        @ptrCast(&aes.iv),
        16,
        plain_text,
        plain_text_size,
        &result,
        @as(win32.NCRYPT_FLAGS, @bitCast(win32.BCRYPT_BLOCK_PADDING))
    );

    if (!nt_success(@enumFromInt(status))) {
        std.log.err("BCryptEncrypt[2] Failed: 0x{:>8}", .{status});
        return false;
    }
    if (plain_text == null) return false;

    aes.plain_text = plain_text;
    aes.plain_size = original_plain_size;

    return true;
}


test "bcrypt encryption" {
    var data = "this is the top secret!".*;

    const key = [_]u8{
            0x2a, 0x21, 0x3e, 0x71, 0xaa, 0x73, 0x4e, 0x5a, 0x88, 0x69, 0x0c, 0x33, 0x46, 0x52, 0xe0, 0xaa,
            0xac, 0xa7, 0x1c, 0x97, 0x18, 0xe0, 0x4c, 0xa9, 0x83, 0x34, 0x2c, 0x18, 0xb5, 0x0a, 0xf7, 0xc6 };
    const iv = [_]u8{
            0xea, 0x1f, 0x08, 0xaa, 0xbc, 0x7e, 0x0b, 0x97, 0x20, 0x38, 0x7f, 0xf6, 0x5b, 0xa7, 0xd8, 0xc9 };
    var aes: AES = .{
        .plain_text = &data[0],
        .plain_size = data.len,
        .cipher_text = null,
        .cipher_size = 0,
        .key = key,
        .iv = iv,
    };

    try std.testing.expectEqual(true, encrypt(&aes));

    const expected = [_]u8{
            0x7c, 0x16, 0x07, 0x4d, 0x2b, 0xcb, 0x1f, 0xf7, 0x36, 0x02, 0x02, 0x42, 0x20, 0x96, 0xe9, 0x32,

            0x7c, 0xe0, 0x34, 0x61, 0xe8, 0xf0, 0x5a, 0xd5, 0xee, 0x56, 0x60, 0x2a, 0x14, 0x88, 0x2e, 0xa1
    };

    try std.testing.expectEqualSlices(u8, &expected, @as([*]u8, @ptrCast(aes.cipher_text.?))[0..aes.cipher_size]);

    defer _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, aes.cipher_text);
}

test "bcrypt decryption" {

    const key = [_]u8{
            0x2a, 0x21, 0x3e, 0x71, 0xaa, 0x73, 0x4e, 0x5a, 0x88, 0x69, 0x0c, 0x33, 0x46, 0x52, 0xe0, 0xaa,
            0xac, 0xa7, 0x1c, 0x97, 0x18, 0xe0, 0x4c, 0xa9, 0x83, 0x34, 0x2c, 0x18, 0xb5, 0x0a, 0xf7, 0xc6 };
    const iv = [_]u8{
            0xea, 0x1f, 0x08, 0xaa, 0xbc, 0x7e, 0x0b, 0x97, 0x20, 0x38, 0x7f, 0xf6, 0x5b, 0xa7, 0xd8, 0xc9 };


    const cipher_text = [_]u8{
            0x7c, 0x16, 0x07, 0x4d, 0x2b, 0xcb, 0x1f, 0xf7, 0x36, 0x02, 0x02, 0x42, 0x20, 0x96, 0xe9, 0x32,
            0x7c, 0xe0, 0x34, 0x61, 0xe8, 0xf0, 0x5a, 0xd5, 0xee, 0x56, 0x60, 0x2a, 0x14, 0x88, 0x2e, 0xa1
    };

    var aes: AES = .{
        .plain_text = null,
        .plain_size = 0,
        .cipher_text = &@constCast(&cipher_text)[0],
        .cipher_size = cipher_text.len,
        .key = key,
        .iv = iv,
    };

    try std.testing.expectEqual(true, decrypt(&aes, 23));

    var expected = "this is the top secret!".*;

    try std.testing.expectEqualSlices(u8, expected[0..], @as([*]u8, @ptrCast(aes.plain_text.?))[0..aes.plain_size]);

    defer _ = win32.HeapFree(win32.GetProcessHeap(), win32.HEAP_NONE, aes.plain_text);
}
