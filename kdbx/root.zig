const std = @import("std");
const xml = @import("xml.zig");
const Allocator = std.mem.Allocator;

// +--------------------------------------------------+
// |Header: Unencrypted                               |
// +--------------------------------------------------+

pub const Header = struct {
    version: HVersion,
    fields: [6]?Field,
    allocator: Allocator,

    const supported_versions = &.{
        .{ 0xB54BFB67, 4 }, // signature and major version
    };

    pub fn readAlloc(reader: anytype, allocator: Allocator) !@This() {
        var j: usize = 0;
        // Read and validate version
        var version: HVersion = undefined;
        _ = reader.readAll(&version.raw) catch |e| {
            std.log.err("Header.read: error while reading version ({any})", .{e});
            return error.UnexpectedError;
        };
        j += 12;

        if (version.getSignature1() != 0x9AA2D903) {
            std.log.err("Header.read: error while reading version", .{});
            return error.InvalidSignature1;
        }

        if (!version.@"versionSupported?"(supported_versions)) {
            std.log.err("Header.read: version {d} is not supported", .{version.getMajorVersion()});
            return error.UnsupportedVersion;
        }

        var fields_: [6]?Field = .{null} ** 6;
        errdefer {
            for (fields_[0..]) |field| {
                if (field) |f| f.deinit();
            }
        }

        // Parse fields
        for (0..7) |i| {
            _ = i;
            const f = Field.readAlloc(reader, allocator, &j) catch |e| {
                return e;
            };
            switch (f) {
                .end_of_header => break,
                else => {},
            }
            fields_[f.getIndex().?] = f; // We already checked that f is not EOH
        }

        if (fields_[0] == null) return error.CipherIdMissing;
        if (fields_[1] == null) return error.CompressionMissing;
        if (fields_[2] == null) return error.MainSeedMissing;
        if (fields_[3] == null) return error.EncryptionIvMissing;
        if (fields_[4] == null) return error.KdfParametersMissing;
        // Public custom data might be missing... this is allowed

        var header: @This() = undefined;
        header.version = version;
        header.allocator = allocator;
        header.fields[0] = fields_[0];
        header.fields[1] = fields_[1];
        header.fields[2] = fields_[2];
        header.fields[3] = fields_[3];
        header.fields[4] = fields_[4];
        header.fields[5] = fields_[5];

        return header;
    }

    pub fn deinit(self: *const @This()) void {
        for (self.fields[0..]) |field| {
            if (field) |f| f.deinit();
        }
    }
};

// # Version
// ####################################################

/// The version information of a KDBX database.
///
/// The first 12 bytes of every KDBX database contain its version information.
pub const HVersion = struct {
    raw: [12]u8,

    /// Create a new version header.
    pub fn new(s1: u32, s2: u32, vmin: u16, vmaj: u16) @This() {
        var tmp: @This() = undefined;
        @memcpy(tmp.raw[0..4], encode(4, s1)[0..]);
        @memcpy(tmp.raw[4..8], encode(4, s2)[0..]);
        @memcpy(tmp.raw[8..10], encode(2, vmin)[0..]);
        @memcpy(tmp.raw[10..12], encode(2, vmaj)[0..]);
        return tmp;
    }

    pub fn @"versionSupported?"(self: *const @This(), versions: []const [2]u32) bool {
        for (versions) |version| {
            if (self.getSignature2() == version[0] and self.getMajorVersion() == version[1])
                return true;
        }
        return false;
    }

    /// Get the first signature. This is always 0x9AA2D903!
    pub fn getSignature1(self: *const @This()) u32 {
        return decode(u32, self.raw[0..4]);
    }

    pub fn setSignature1(self: *@This(), s: u32) void {
        @memcpy(self.raw[0..4], encode(4, s)[0..]);
    }

    /// Get the second signature. The signature depends on the version of the database.
    pub fn getSignature2(self: *const @This()) u32 {
        return decode(u32, self.raw[4..8]);
    }

    pub fn setSignature2(self: *@This(), s: u32) void {
        @memcpy(self.raw[4..8], encode(4, s)[0..]);
    }

    /// Get the minor version number, e.g. `1` for v4.1.
    pub fn getMinorVersion(self: *const @This()) u16 {
        return decode(u16, self.raw[8..10]);
    }

    pub fn setMinorVersion(self: *@This(), v: u16) void {
        @memcpy(self.raw[8..10], encode(2, v)[0..]);
    }

    /// Get the major version number, e.g. `4` for v4.1.
    pub fn getMajorVersion(self: *const @This()) u16 {
        return decode(u16, self.raw[10..12]);
    }

    pub fn setMajorVersion(self: *@This(), v: u16) void {
        @memcpy(self.raw[10..12], encode(2, v)[0..]);
    }
};

// # Fields
// ####################################################

pub const FieldTag = enum(u8) {
    end_of_header = 0,
    cipher_id = 2,
    compression = 3,
    main_seed = 4,
    encryption_iv = 7,
    kdf_parameters = 11,
    public_custom_data = 12,

    pub fn total() usize {
        return 7;
    }
};

pub const Field = union(FieldTag) {
    end_of_header: struct {},
    cipher_id: Cipher,
    compression: Compression,
    main_seed: MainSeed,
    encryption_iv: [16]u8,
    kdf_parameters: union(KdfTag) {
        aes: struct {
            /// Number of rounds
            r: u64,
            /// A random seeed
            s: [32]u8,
        },
        argon2: struct {
            /// A random salt
            s: [32]u8,
            /// Parallelism
            p: u32,
            /// Memory usage in bytes
            m: u64,
            /// Iterations
            i: u64,
            /// Argon2 version (either 0x10 or 0x13)
            v: u32,
            /// Optional key
            k: ?[]const u8 = null,
            /// Optional associated data
            a: ?[]const u8 = null,
            allocator: Allocator,

            pub fn deinit(self: *const @This()) void {
                if (self.k) |k| {
                    self.allocator.free(k);
                }
                if (self.a) |a| {
                    self.allocator.free(a);
                }
            }
        },
    },
    public_custom_data: struct {
        fields: []const VField,
        allocator: Allocator,

        pub fn deinit(self: *const @This()) void {
            for (self.fields) |field| {
                field.deinit(self.allocator);
            }
            self.allocator.free(self.fields);
        }
    },

    pub const Cipher = enum(u128) {
        aes128_cbc = 0x35DDF83D563A748DC3416494A105AB61,
        aes256_cbc = 0xFF5AFC6A210558BE504371BFE6F2C131,
        twofish_cbc = 0x6C3465F97AD46AA3B94B6F579FF268AD,
        chacha20 = 0x9AB5DB319A3324A5B54C6F8B2B8A03D6,

        pub fn fromSlice(s: []const u8) !@This() {
            if (s.len != 16) return error.InvalidSize;
            const v = decode(u128, s);
            return switch (v) {
                0x35DDF83D563A748DC3416494A105AB61 => .aes128_cbc,
                0xFF5AFC6A210558BE504371BFE6F2C131 => .aes256_cbc,
                0x6C3465F97AD46AA3B94B6F579FF268AD => .twofish_cbc,
                0x9AB5DB319A3324A5B54C6F8B2B8A03D6 => .chacha20,
                else => error.UnsupportedCipher,
            };
        }
    };

    pub const Compression = enum(u32) {
        none = 0,
        gzip = 1,

        pub fn fromSlice(s: []const u8) !@This() {
            if (s.len != 4) return error.InvalidSize;
            const v = decode(u32, s);
            return switch (v) {
                0 => .none,
                1 => .gzip,
                else => error.UnsupportedCompression,
            };
        }
    };

    pub const MainSeed = [32]u8;

    pub const KdfTag = enum {
        aes,
        argon2,
    };

    pub const Kdf = enum(u128) {
        aes_kdf = 0xea4f8ac1080d74bf60448a629af3d9c9,
        argon2d = 0x0c0ae303a4a9f7914b44298cdf6d63ef,
        argon2id = 0xe6a1f0c63efc3db27347db56198b299e,
    };

    pub fn getIndex(self: *const @This()) ?usize {
        return switch (self.*) {
            .cipher_id => 0,
            .compression => 1,
            .main_seed => 2,
            .encryption_iv => 3,
            .kdf_parameters => 4,
            .public_custom_data => 5,
            .end_of_header => null,
        };
    }

    pub fn readAlloc(reader: anytype, allocator: Allocator, j: *usize) !@This() {
        const t = try reader.readByte();
        j.* += 1;
        const size: usize = @intCast(try reader.readInt(u32, .little));
        j.* += 4;
        var m = try allocator.alloc(u8, size);
        for (m) |*b| b.* = try reader.readByte();
        //const m = try reader.readAllAlloc(allocator, size);
        defer allocator.free(m);
        j.* += m.len;
        if (m.len != size) return error.UnexpectedLength;

        return switch (t) {
            0 => Field{ .end_of_header = .{} },
            2 => Field{ .cipher_id = try Cipher.fromSlice(m) },
            3 => Field{ .compression = try Compression.fromSlice(m) },
            4 => blk: {
                if (m.len != 32) break :blk error.InvalidSize;
                break :blk Field{ .main_seed = m[0..32].* };
            },
            7 => blk: {
                if (m.len > 16) break :blk error.InvalidSize;
                // The acutal length is determined by the cipher. If aes is
                // used it is 16, otherwise (for chacha20) it is 12.
                var iv: [16]u8 = .{0} ** 16;
                @memcpy(iv[0..m.len], m);
                break :blk Field{ .encryption_iv = iv };
            },
            11 => blk: {
                var n: usize = 0;

                if (m.len < 2) return error.InvalidLength;
                const format = decode(u16, m[n .. n + 2]);
                if (format & 0xff00 != 0x100) break :blk error.InvalidVariantMapFormat;
                n += 2;

                var kdf_: ?Kdf = null;
                var r_: ?u64 = null;
                var s_: ?[32]u8 = null;
                var p_: ?u32 = null;
                var m_: ?u64 = null;
                var i_: ?u64 = null;
                var v_: ?u32 = null;
                var k_: ?[]const u8 = null;
                var a_: ?[]const u8 = null;

                while (n < m.len) {
                    if (m[n] == 0) break; // EOF

                    const vt = m[n];
                    n += 1;

                    if (n + 4 >= m.len) return error.InvalidLength;
                    var s: usize = @intCast(decode(u16, m[n .. n + 4]));
                    n += 4;

                    if (n + s >= m.len) return error.InvalidLength;
                    const k = m[n .. n + s];
                    n += s;

                    if (n + 4 >= m.len) return error.InvalidLength;
                    s = @intCast(decode(u16, m[n .. n + 4]));
                    n += 4;

                    if (n + s >= m.len) return error.InvalidLength;
                    const v = m[n .. n + s];
                    n += s;

                    const vf = VField{
                        .type = try VField.Type.fromByte(vt),
                        .key = k,
                        .value = v,
                    };

                    if (std.mem.eql(u8, vf.key, "R")) {
                        r_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "S")) {
                        const b_ = vf.getByte();
                        if (b_ == null or b_.?.len != 32) return error.AesKdfSeed;
                        s_ = b_.?[0..32].*;
                    } else if (std.mem.eql(u8, vf.key, "$UUID")) {
                        if (vf.value.len != 16) return error.InvalidUuidLength;
                        const uuid = decode(u128, vf.value);
                        switch (uuid) {
                            0xea4f8ac1080d74bf60448a629af3d9c9 => kdf_ = .aes_kdf,
                            0x0c0ae303a4a9f7914b44298cdf6d63ef => kdf_ = .argon2d,
                            0xe6a1f0c63efc3db27347db56198b299e => kdf_ = .argon2id,
                            else => {},
                        }
                    } else if (std.mem.eql(u8, vf.key, "P")) {
                        p_ = vf.getUInt32();
                    } else if (std.mem.eql(u8, vf.key, "M")) {
                        m_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "I")) {
                        i_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "V")) {
                        v_ = vf.getUInt32();
                    } else if (std.mem.eql(u8, vf.key, "K")) {
                        k_ = vf.getByte();
                    } else if (std.mem.eql(u8, vf.key, "A")) {
                        a_ = vf.getByte();
                    }
                }

                if (kdf_ == null) return error.KdfUuidMissing;
                switch (kdf_.?) {
                    .aes_kdf => {
                        if (r_ == null) break :blk error.KdfRMissing;
                        if (s_ == null) break :blk error.KdfSMissing;
                        break :blk Field{
                            .kdf_parameters = .{ .aes = .{
                                .r = r_.?,
                                .s = s_.?[0..32].*,
                            } },
                        };
                    },
                    .argon2d, .argon2id => {
                        if (s_ == null) break :blk error.KdfSMissing;
                        if (p_ == null) break :blk error.KdfPMissing;
                        if (m_ == null) break :blk error.KdfMMissing;
                        if (i_ == null) break :blk error.KdfIMissing;
                        if (v_ == null) break :blk error.KdfVMissing;
                        var a = Field{
                            .kdf_parameters = .{ .argon2 = .{
                                .s = s_.?[0..32].*,
                                .p = p_.?,
                                .m = m_.?,
                                .i = i_.?,
                                .v = v_.?,
                                .allocator = allocator,
                            } },
                        };
                        errdefer {
                            if (a.kdf_parameters.argon2.k) |k__| allocator.free(k__);
                            if (a.kdf_parameters.argon2.a) |a__| allocator.free(a__);
                        }

                        if (k_) |k__| a.kdf_parameters.argon2.k =
                            try allocator.dupe(u8, k__);
                        if (a_) |a__| a.kdf_parameters.argon2.k =
                            try allocator.dupe(u8, a__);

                        break :blk a;
                    },
                }
            },
            else => error.InvalidHeaderField,
        };
    }

    pub fn deinit(self: *const @This()) void {
        switch (self.*) {
            .kdf_parameters => |kdf| {
                switch (kdf) {
                    .argon2 => |argon| {
                        argon.deinit();
                    },
                    else => {},
                }
            },
            .public_custom_data => |pcd| {
                pcd.deinit();
            },
            else => {},
        }
    }
};

pub const VField = struct {
    type: Type,
    key: []const u8,
    value: []const u8,

    pub const Type = enum(u8) {
        UInt32 = 0x04,
        UInt64 = 0x05,
        Bool = 0x08,
        Int32 = 0x0c,
        Int64 = 0x0d,
        String = 0x18,
        Byte = 0x42,

        pub fn fromByte(b: u8) !@This() {
            return switch (b) {
                0x04 => .UInt32,
                0x05 => .UInt64,
                0x08 => .Bool,
                0x0c => .Int32,
                0x0d => .Int64,
                0x18 => .String,
                0x42 => .Byte,
                else => error.InvalidVFieldType,
            };
        }
    };

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }

    pub fn getUInt32(self: *const @This()) ?u32 {
        if (self.type != .UInt32) return null;
        if (self.value.len != 4) return null;
        return decode(u32, self.value);
    }

    pub fn getUInt64(self: *const @This()) ?u64 {
        if (self.type != .UInt64) return null;
        if (self.value.len != 8) return null;
        return decode(u64, self.value);
    }

    pub fn getBool(self: *const @This()) ?bool {
        if (self.type != .Bool) return null;
        if (self.value.len != 1) return null;
        return self.value[0] != 0;
    }

    pub fn getInt32(self: *const @This()) ?i32 {
        if (self.type != .Int32) return null;
        if (self.value.len != 4) return null;
        return decode(i32, self.value);
    }

    pub fn getInt64(self: *const @This()) ?i64 {
        if (self.type != .Int64) return null;
        if (self.value.len != 8) return null;
        return decode(i64, self.value);
    }

    pub fn getString(self: *const @This()) ?[]const u8 {
        if (self.type != .String) return null;
        return self.value;
    }

    pub fn getByte(self: *const @This()) ?[]const u8 {
        if (self.type != .Byte) return null;
        return self.value;
    }
};

// +--------------------------------------------------+
// |Misc                                              |
// +--------------------------------------------------+

fn encode(comptime n: usize, int: anytype) [n]u8 {
    var tmp: [n]u8 = undefined;

    inline for (0..n) |i| {
        tmp[i] = @intCast((int >> (@as(u5, @intCast(i)) * 8)) & 0xff);
    }

    return tmp;
}

fn decode(T: type, arr: anytype) T {
    const bytes = @typeInfo(T).Int.bits / 8;
    var tmp: T = 0;

    for (0..bytes) |i| {
        tmp <<= 8;
        tmp += arr[bytes - (i + 1)];
    }

    return tmp;
}

// +--------------------------------------------------+
// |Tests                                             |
// +--------------------------------------------------+

test "HVersion #1" {
    var v = HVersion.new(0x9AA2D903, 0xB54BFB67, 1, 4);

    try std.testing.expectEqualSlices(u8, "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00", &v.raw);
    try std.testing.expectEqual(@as(u32, 0x9AA2D903), v.getSignature1());
    try std.testing.expectEqual(@as(u32, 0xB54BFB67), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 1), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 4), v.getMajorVersion());

    v.setSignature2(0xcafebabe);
    v.setMinorVersion(3);
    v.setMajorVersion(5);
    try std.testing.expectEqual(@as(u32, 0xcafebabe), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 3), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 5), v.getMajorVersion());
}

test "decode outer header" {
    const s = "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00\x02\x10\x00\x00\x00\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff\x03\x04\x00\x00\x00\x01\x00\x00\x00\x04\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x07\x10\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x0b\x8b\x00\x00\x00\x00\x01\x42\x05\x00\x00\x00\x24\x55\x55\x49\x44\x10\x00\x00\x00\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c\x05\x01\x00\x00\x00\x49\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x4d\x08\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x04\x01\x00\x00\x00\x50\x04\x00\x00\x00\x08\x00\x00\x00\x42\x01\x00\x00\x00\x53\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x04\x01\x00\x00\x00\x56\x04\x00\x00\x00\x13\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a";

    var fbs = std.io.fixedBufferStream(s);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    header.deinit();
}
