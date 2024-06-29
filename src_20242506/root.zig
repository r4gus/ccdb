const std = @import("std");
const tests = @import("tests.zig");
const cbor = @import("zbor");

const argon2 = std.crypto.pwhash.argon2;
const HkdfSha512 = std.crypto.kdf.hkdf.HkdfSha512;
const chacha = @import("chacha.zig");
const XChaCha20IETF = chacha.XChaCha20IETF;

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

pub const Body = struct {
    meta: Meta,
};

pub const Meta = struct {
    iv: []u8,
    gen: []u8,
    name: []u8,
    times: []u8,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        @memset(self.iv, 0);
        allocator.free(self.iv);
        @memset(self.gen, 0);
        allocator.free(self.gen);
        @memset(self.name, 0);
        allocator.free(self.name);
        @memset(self.times, 0);
        allocator.free(self.times);
    }

    pub fn updateAlloc(
        self: *const @This(),
        gen: ?[]const u8,
        name: ?[]const u8,
        times: ?Times,
        ms: *const MasterSecret,
        allocator: std.mem.Allocator,
    ) !void {
        if (gen == null and name == null and times == null) return; // nothing to do

        var k: [32]u8 = undefined;
        defer @memset(k[0..], 0);
        ms.deriveMetaKey(&k);

        const new_iv = try allocator.alloc(u8, 24);
        errdefer {
            @memset(new_iv, 0);
            allocator.free(new_iv);
        }
        std.crypto.random.bytes(new_iv);


    }

    pub fn getGenAlloc(
        self: *const @This(),
        allocator: std.mem.Allocator,
        ms: *const MasterSecret,
    ) ![]const u8 {
        var k: [32]u8 = undefined;
        defer @memset(k[0..], 0);
        ms.deriveMetaKey(&k);

        const gen = try allocator.dupe(u8, self.gen);
        errdefer {
            @memset(gen, 0);
            allocator.free(gen);
        }
        XChaCha20IETF.seekXor(gen, 0, k, self.iv[0..24].*, 0);

        return gen;
    }

    pub fn getNameAlloc(
        self: *const @This(),
        allocator: std.mem.Allocator,
        ms: *const MasterSecret,
    ) ![]const u8 {
        var k: [32]u8 = undefined;
        defer @memset(k[0..], 0);
        ms.deriveMetaKey(&k);

        const name = try allocator.dupe(u8, self.name);
        errdefer {
            @memset(name, 0);
            allocator.free(name);
        }
        XChaCha20IETF.seekXor(name, 0, k, self.iv[0..24].*, self.gen.len);

        return name;
    }

    pub fn getTimes(
        self: *const @This(),
        ms: *const MasterSecret,
    ) !Times {
        var buf: [128]u8 = undefined;
        defer @memset(buf[0..], 0);

        var k: [32]u8 = undefined;
        defer @memset(k[0..], 0);
        ms.deriveMetaKey(&k);

        @memcpy(buf[0..self.times.len], self.times);
        XChaCha20IETF.seekXor(
            buf[0..self.times.len],
            0,
            k,
            self.iv[0..24].*,
            self.gen.len + self.name.len,
        );

        return cbor.parse(Times, try cbor.DataItem.new(buf[0..self.times.len]), .{});
    }

    pub fn new(
        gen: []const u8,
        name: []const u8,
        allocator: std.mem.Allocator,
        ms: *const MasterSecret,
    ) !@This() {
        var k: [32]u8 = undefined;
        defer @memset(k[0..], 0);
        ms.deriveMetaKey(&k);

        // A 24 bytes nonce is large enough to select it at random.
        const iv = try allocator.alloc(u8, 24);
        errdefer allocator.free(iv);
        std.crypto.random.bytes(iv);

        const t = Times.new(null, null);
        var times = std.ArrayList(u8).init(allocator);
        errdefer times.deinit();
        try cbor.stringify(t, .{}, times.writer());

        var m = Meta{
            .iv = iv,
            .gen = try allocator.dupe(u8, gen),
            .name = try allocator.dupe(u8, name),
            .times = try times.toOwnedSlice(),
        };

        // Now generate the key stream to be applied to the individual fields
        const x = try allocator.alloc(u8, m.gen.len + m.name.len + m.times.len);
        defer {
            @memset(x, 0);
            allocator.free(x);
        }
        XChaCha20IETF.stream(x, 0, k, m.iv[0..24].*);

        var j: usize = 0;
        for (0..m.gen.len) |i| {
            m.gen[i] ^= x[j];
            j += 1;
        }
        for (0..m.name.len) |i| {
            m.name[i] ^= x[j];
            j += 1;
        }
        for (0..m.times.len) |i| {
            m.times[i] ^= x[j];
            j += 1;
        }

        return m;
    }

    pub fn cborStringify(self: *const @This(), _: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "iv", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "gen", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "name", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "times", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
        }, out);
    }
};

pub const Times = struct {
    creat: i64,
    mod: i64,
    exp: ?i64 = null,
    cnt: ?usize = null,

    pub fn new(exp: ?i64, cnt: ?usize) @This() {
        const t = std.time.milliTimestamp();
        return .{
            .creat = t,
            .mod = t,
            .exp = exp,
            .cnt = cnt,
        };
    }

    pub fn cborStringify(self: *const @This(), _: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "creat", .field_options = .{ .alias = "0", .serialization_type = .Integer } },
                .{ .name = "mod", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "exp", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "cnt", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            },
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, _: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "creat", .field_options = .{ .alias = "0", .serialization_type = .Integer } },
                .{ .name = "mod", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "exp", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "cnt", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            },
        });
    }
};

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

/// Wrapper for the DECRYPTED master secret.
///
/// The owner MUST call deinit() before the object is dropped!
pub const MasterSecret = struct {
    ms: [64]u8,

    pub fn deinit(self: *@This()) void {
        @memset(self.ms[0..], 0);
    }

    pub fn deriveEntryKey(self: *const @This(), out: []u8, index: u32) void {
        var ctx: [4]u8 = undefined;
        ctx[0] = @intCast(index & 0xff);
        ctx[1] = @intCast(index >> 8 & 0xff);
        ctx[2] = @intCast(index >> 16 & 0xff);
        ctx[3] = @intCast(index >> 24 & 0xff);
        defer @memset(&ctx, 0);

        HkdfSha512.expand(out, ctx[0..], self.ms);
    }

    pub fn deriveMetaKey(self: *const @This(), out: []u8) void {
        HkdfSha512.expand(out, "meta", self.ms);
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
