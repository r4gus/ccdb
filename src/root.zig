const std = @import("std");
const tests = @import("tests.zig");

pub const Ccdb = struct {
    version: Version = .{},
    body: Body,
    header: Header,
    allocator: std.mem.Allocator,
};

// +-------------------------------------------------------+
// | Version                                               |
// +-------------------------------------------------------+

pub const Version = struct {
    sig: [4]u8 = "CCDB".*,
    major_version: u16 = 1,
    minor_version: u16 = 0,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll("CCDB");
        try writer.writeByte(@as(u8, @intCast(self.major_version & 0xff)));
        try writer.writeByte(@as(u8, @intCast(self.major_version >> 8 & 0xff)));
        try writer.writeByte(@as(u8, @intCast(self.minor_version & 0xff)));
        try writer.writeByte(@as(u8, @intCast(self.minor_version >> 8 & 0xff)));
    }
};

// +-------------------------------------------------------+
// | Body                                                  |
// +-------------------------------------------------------+

pub const Body = struct {};

// +-------------------------------------------------------+
// | Header                                                |
// +-------------------------------------------------------+

pub const Header = struct {
    fields: HeaderFields,
    /// Currently the only cipher is XChaCha20 with a key length of 32 bytes.
    master_secret: [32]u8,
    /// Currently the only cipher AEAD cipher is XChaCha20-Poly1305 with a tag length of 16 bytes.
    tag: [16]u8,
};

pub const HeaderFields = struct {
    /// Currently the only cipher is XChaCha20 with a iv length of 24 bytes.
    /// This value is large enough to be chosen at random without risking collisions.
    iv: [24]u8,
    cid: [30]u8 = "CCDB_XCHACHA20_POLY1305_SHA512".*,
    kdf: KdfParams,
    ext: []const []const u8,
};

pub const KdfParams = struct {
    /// Argon2id is the default.
    @"$UUID": [36]u8 = "9e298b19-56db-4773-b23d-fc3ec6f0a1e6",
    /// Argon2id: Iterations
    I: ?u64 = null,
    /// Argon2id: Memory usage
    M: ?u64 = null,
    /// Argon2id: Parallelism
    P: ?u32 = null,
    /// Argon2id: Random Salt
    S: ?[32]u8 = null,
};

// +-------------------------------------------------------+
// | Misc                                                  |
// +-------------------------------------------------------+

pub fn readBytes(slice: []const u8, n: usize, offset: *usize, update_offset: bool) ![]const u8 {
    if (offset + n > slice.len) return error.EndOfSlice;
    defer {
        if (update_offset) offset.* += n;
    }

    return slice[offset.* .. offset.* + n];
}

test "root tests" {
    _ = tests;
}
