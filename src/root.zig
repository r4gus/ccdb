const std = @import("std");
const tests = @import("tests.zig");
const cbor = @import("zbor");

const argon2 = std.crypto.pwhash.argon2;

pub const Ccdb = struct {
    version: Version = .{},
    body: Body,
    header: Trailer,
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
// | Trailer                                               |
// +-------------------------------------------------------+

pub const Trailer = struct {
    fields: TrailerFields,
    master_secret: []const u8,
    tag: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const @This()) void {
        self.fields.deinit(self.allocator);

        @memset(self.master_secret, 0);
        self.allocator.free(self.master_secret);

        @memset(self.tag, 0);
        self.allocator.free(self.tag);
    }
};

pub const TrailerFields = struct {
    iv: []const u8,
    cid: []const u8,
    kdf: KdfParams,
    ext: []const []const u8,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.iv);
        allocator.free(self.cid);
        for (self.ext) |e| {
            allocator.free(e);
        }
        allocator.free(self.ext);
    }

    /// Derive the encryption key, used to en-/decrypt the master secret
    /// from a user secret. The user secret is the concatenation of the
    /// following values: `password || keyFileContent || keyProviderContent`.
    pub fn deriveEncryptionKey(
        self: *const @This(),
        out: []u8,
        user_secret: []const u8,
        allocator: std.mem.Allocator,
    ) !void {
        if (std.mem.eql(u8, &self.kdf.@"$UUID", "9e298b19-56db-4773-b23d-fc3ec6f0a1e6")) {
            if (self.kdf.I == null or self.kdf.M == null or self.kdf.P == null or self.kdf.S == null) {
                return error.MissingKdfParam;
            }

            try argon2.kdf(
                allocator,
                out,
                user_secret,
                self.kdf.S.?[0..],
                .{
                    .t = self.kdf.I.?,
                    .m = self.kdf.M.?,
                    .p = self.kdf.P.?,
                },
                .argon2id,
            );
        } else {
            return error.UnsupportedKdf;
        }
    }

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
        _ = options;

        try cbor.stringify(self, .{
            .field_settings = &.{
                .{ .name = "iv", .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "cid", .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "ext", .value_options = .{ .slice_serialization_type = .TextString } },
            },
            .from_callback = true,
        }, out);
    }
};

pub const KdfParams = struct {
    /// Argon2id is the default.
    @"$UUID": [36]u8 = "9e298b19-56db-4773-b23d-fc3ec6f0a1e6".*,
    /// Argon2id: Iterations
    I: ?u32 = null,
    /// Argon2id: Memory usage
    M: ?u32 = null,
    /// Argon2id: Parallelism
    P: ?u24 = null,
    /// Argon2id: Random Salt
    S: ?[32]u8 = null,

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
        _ = options;

        try cbor.stringify(self, .{
            .field_settings = &.{
                .{ .name = "$UUID", .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "S", .value_options = .{ .slice_serialization_type = .ByteString } },
            },
            .from_callback = true,
        }, out);
    }
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
