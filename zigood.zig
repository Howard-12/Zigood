pub const xor = @import("src/encryption/xor.zig");
pub const rc41 = @import("src/encryption/rc4.zig");
pub const rc42 = @import("src/encryption/rc42.zig");
pub const aes = @import("src/encryption/aes.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

