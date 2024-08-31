//! KDBX4 Password Database File Format
//!
//! Note: All numbers are stored using the little-endian format.

const std = @import("std");

// +--------------------------------------------------+
// |Header: Unencrypted                               |
// +--------------------------------------------------+

pub const Header = struct {
    version: HVersion,
    fields: []const u8,
    indices: [13]?[2]usize,

    pub fn new(raw: []const u8) !@This() {
        // First validate version fields...

        if (raw.len < 12) return error.UnexpectedEndOfSlice;
        const version = HVersion{ .raw = raw[0..12].* };
        if (version.getSignature1() != 0x9AA2D903) return error.InvalidSignature1;
        // For now we just support KDBX4
        if (version.getSignature2() != 0xB54BFB67) return error.InvalidSignature2;

        // Next, seek to header end...
        var indices: [13]?[2]usize = .{null} ** 13;
        var i: usize = 12;
        while (true) {
            if (i + 5 >= raw.len) return error.UnexpectedEndOfSlice;
            const l: usize = @intCast(decode(u32, raw[i + 1 .. i + 5]));
            if (i + 5 + l > raw.len) return error.UnexpectedEndOfSlice;
            const t = raw[i];
            indices[@as(usize, @intCast(t))] = .{ i - 12, i + l + 5 - 12 };
            i += l + 5;

            if (t == @intFromEnum(Field.Type.end_of_header)) break;
        }

        return .{
            .version = version,
            .fields = raw[12..i],
            .indices = indices,
        };
    }

    pub fn getField(self: *const @This(), field: Field.Type) ?Field {
        if (self.indices[@intFromEnum(field)]) |i| {
            const s, const e = i;
            return Field{ .raw = self.fields[s..e] };
        } else return null;
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

pub const Field = struct {
    raw: []const u8,

    pub const MainSeed = [32]u8;
    pub const ChaCha20Iv = [12]u8;
    pub const CbcIv = [16]u8;

    pub const Type = enum(u8) {
        end_of_header = 0,
        cipher_id = 2,
        compression = 3,
        main_seed = 4,
        encryption_iv = 7,
        kdf_parameters = 11,
        public_custom_data = 12,
    };

    pub const Compression = enum(u32) {
        none = 0,
        gzip = 1,
    };

    pub const Cipher = enum(u128) {
        aes128_cbc = 0x35DDF83D563A748DC3416494A105AB61,
        aes256_cbc = 0xFF5AFC6A210558BE504371BFE6F2C131,
        twofish_cbc = 0x6C3465F97AD46AA3B94B6F579FF268AD,
        chacha20 = 0x9AB5DB319A3324A5B54C6F8B2B8A03D6,
    };

    pub fn getType(self: *const @This()) Type {
        return @enumFromInt(self.raw[0]);
    }

    pub fn getSize(self: *const @This()) u32 {
        return decode(u32, self.raw[1..5]);
    }

    pub fn getTotalSize(self: *const @This()) usize {
        return @intCast(decode(u32, self.raw[1..5]) + 5);
    }

    pub fn isEOH(self: *const @This()) bool {
        return self.getType() == .end_of_header;
    }

    pub fn getCipherId(self: *const @This()) Cipher {
        return @enumFromInt(decode(u128, self.raw[5..21]));
    }

    pub fn getCompression(self: *const @This()) Compression {
        return @enumFromInt(decode(u32, self.raw[5..9]));
    }

    pub fn getMainSeed(self: *const @This()) MainSeed {
        return self.raw[5..37].*;
    }

    pub fn getEncryptionIvChaCha20(self: *const @This()) ChaCha20Iv {
        return self.raw[5..17].*;
    }

    pub fn getEncryptionIvCbc(self: *const @This()) CbcIv {
        return self.raw[5..21].*;
    }

    pub fn getKdfParameters(self: *const @This()) !VariantMap {
        const slice = self.raw[5 .. 5 + @as(usize, @intCast(self.getSize()))];
        if (slice[1] != 0x01) return error.InvalidVersionNumber;
        return VariantMap.new(slice[2..]);
    }
};

// # VariantMap
// ####################################################

pub const VariantField = struct {
    raw: []const u8,
    allocator: ?std.mem.Allocator = null,

    pub const Type = enum(u8) {
        uint32 = 4,
        uint64 = 5,
        boolean = 8,
        int32 = 0xc,
        int64 = 0xd,
        string = 0x18,
        byte = 0x42,
    };

    pub const Kdf = enum(u128) {
        aes_kdf = 0xea4f8ac1080d74bf60448a629af3d9c9,
        argon2d = 0x0c0ae303a4a9f7914b44298cdf6d63ef,
        argon2id = 0xe6a1f0c63efc3db27347db56198b299e,
    };

    pub fn deinit(self: *const @This()) void {
        if (self.allocator) |a| a.free(self.raw);
    }

    pub fn getType(self: *const @This()) Type {
        return @enumFromInt(self.raw[0]);
    }

    fn getKeySize(self: *const @This()) usize {
        return @intCast(decode(u32, self.raw[1..5]));
    }

    pub fn getKey(self: *const @This()) []const u8 {
        return self.raw[5 .. 5 + self.getKeySize()];
    }

    fn getValueSize(self: *const @This()) usize {
        const ks: usize = @intCast(decode(u32, self.raw[1..5]));
        return @intCast(decode(u32, self.raw[5 + ks .. 5 + ks + 4]));
    }

    pub fn getValue(self: *const @This()) []const u8 {
        const ks = self.getKeySize();
        const vs = self.getValueSize();
        return self.raw[9 + ks .. 9 + ks + vs];
    }

    pub fn getUint32(self: *const @This()) u32 {
        return decode(u32, self.getValue());
    }

    pub fn getUint64(self: *const @This()) u64 {
        return decode(u64, self.getValue());
    }

    pub fn getBool(self: *const @This()) bool {
        return self.getValue()[0] != 0;
    }

    pub fn getInt32(self: *const @This()) i32 {
        return decode(i32, self.getValue());
    }

    pub fn getInt64(self: *const @This()) i64 {
        return decode(i64, self.getValue());
    }

    pub fn getString(self: *const @This()) []const u8 {
        return self.getValue();
    }

    pub fn getByte(self: *const @This()) []const u8 {
        return self.getValue();
    }
};

pub const VariantMap = struct {
    raw: []const u8,
    indices: [13]?[2]usize,

    const types = struct {
        const @"$UUID" = 0;
        const R = 1;
        const S = 2;
        const P = 3;
        const M = 4;
        const I = 5;
        const V = 6;
        const K = 7;
        const A = 8;
    };

    pub fn new(raw: []const u8) !@This() {
        var this = @This(){
            .raw = raw,
            .indices = .{null} ** 13,
        };

        var i: usize = 0;
        while (true) {
            if (i >= this.raw.len or this.raw[i] == 0) break;
            if (i + 5 >= this.raw.len) return error.UnexpectedEndOfSlice;

            const ks: usize = @intCast(decode(u32, this.raw[i + 1 .. i + 5]));
            if (i + 5 + ks >= this.raw.len) return error.UnexpectedEndOfSlice;

            const vs: usize = @intCast(decode(u32, this.raw[i + 5 + ks .. i + 5 + ks + 4]));
            if (i + 5 + ks + 4 + vs >= this.raw.len) return error.UnexpectedEndOfSlice;
            const start = i;
            const end = i + 5 + ks + 4 + vs;

            const vf = VariantField{ .raw = this.raw[start..end] };

            if (std.mem.eql(u8, "$UUID", vf.getKey())) {
                this.indices[types.@"$UUID"] = .{ start, end };
            } else if (std.mem.eql(u8, "R", vf.getKey())) {
                this.indices[types.R] = .{ start, end };
            } else if (std.mem.eql(u8, "S", vf.getKey())) {
                this.indices[types.S] = .{ start, end };
            } else if (std.mem.eql(u8, "P", vf.getKey())) {
                this.indices[types.P] = .{ start, end };
            } else if (std.mem.eql(u8, "M", vf.getKey())) {
                this.indices[types.M] = .{ start, end };
            } else if (std.mem.eql(u8, "I", vf.getKey())) {
                this.indices[types.I] = .{ start, end };
            } else if (std.mem.eql(u8, "V", vf.getKey())) {
                this.indices[types.V] = .{ start, end };
            } else if (std.mem.eql(u8, "K", vf.getKey())) {
                this.indices[types.K] = .{ start, end };
            } else if (std.mem.eql(u8, "A", vf.getKey())) {
                this.indices[types.A] = .{ start, end };
            } // unknown fields are ignored

            i = end;
        }

        return this;
    }

    pub fn get(self: *@This(), key: []const u8) ?VariantField {
        const idx = if (std.mem.eql(u8, "$UUID", key)) blk: {
            break :blk self.indices[types.@"$UUID"];
        } else if (std.mem.eql(u8, "R", key)) blk: {
            break :blk self.indices[types.R];
        } else if (std.mem.eql(u8, "S", key)) blk: {
            break :blk self.indices[types.S];
        } else if (std.mem.eql(u8, "P", key)) blk: {
            break :blk self.indices[types.P];
        } else if (std.mem.eql(u8, "M", key)) blk: {
            break :blk self.indices[types.M];
        } else if (std.mem.eql(u8, "I", key)) blk: {
            break :blk self.indices[types.I];
        } else if (std.mem.eql(u8, "V", key)) blk: {
            break :blk self.indices[types.V];
        } else if (std.mem.eql(u8, "K", key)) blk: {
            break :blk self.indices[types.K];
        } else if (std.mem.eql(u8, "A", key)) blk: {
            break :blk self.indices[types.A];
        } else null;

        if (idx == null) return null;
        return .{ .raw = self.raw[idx.?[0]..idx.?[1]] };
    }

    pub fn getUuid(self: *@This()) ?VariantField.Kdf {
        const v = if (self.get("$UUID")) |id| id.getValue() else return null;
        if (v.len != 16) return null;
        return @enumFromInt(decode(u128, v));
    }

    pub fn getR(self: *@This()) ?u64 {
        const v = if (self.get("R")) |v| v.getValue() else return null;
        if (v.len != 8) return null;
        return decode(u64, v);
    }

    pub fn getS(self: *@This()) ?[]const u8 {
        const v = if (self.get("S")) |v| v.getValue() else return null;
        return v;
    }

    pub fn getP(self: *@This()) ?u32 {
        const v = if (self.get("P")) |v| v.getValue() else return null;
        if (v.len != 4) return null;
        return decode(u32, v);
    }

    pub fn getM(self: *@This()) ?u64 {
        const v = if (self.get("M")) |v| v.getValue() else return null;
        if (v.len != 8) return null;
        return decode(u64, v);
    }

    pub fn getI(self: *@This()) ?u64 {
        const v = if (self.get("I")) |v| v.getValue() else return null;
        if (v.len != 8) return null;
        return decode(u64, v);
    }

    pub fn getV(self: *@This()) ?u32 {
        const v = if (self.get("V")) |v| v.getValue() else return null;
        if (v.len != 4) return null;
        return decode(u32, v);
    }

    pub fn getK(self: *@This()) ?[]const u8 {
        const v = if (self.get("K")) |v| v.getValue() else return null;
        return v;
    }

    pub fn getA(self: *@This()) ?[]const u8 {
        const v = if (self.get("A")) |v| v.getValue() else return null;
        return v;
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

    const h = try Header.new(s);

    const cid = h.getField(.cipher_id).?;
    try std.testing.expectEqual(Field.Type.cipher_id, cid.getType());
    try std.testing.expectEqual(Field.Cipher.aes256_cbc, cid.getCipherId());

    const comp = h.getField(.compression).?;
    try std.testing.expectEqual(Field.Type.compression, comp.getType());
    try std.testing.expectEqual(Field.Compression.gzip, comp.getCompression());

    const seed = h.getField(.main_seed).?;
    try std.testing.expectEqual(Field.Type.main_seed, seed.getType());
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &seed.getMainSeed());

    const iv = h.getField(.encryption_iv).?;
    try std.testing.expectEqual(Field.Type.encryption_iv, iv.getType());
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &iv.getEncryptionIvCbc());

    const kdf = h.getField(.kdf_parameters).?;
    try std.testing.expectEqual(Field.Type.kdf_parameters, kdf.getType());
    var kdf_params = try kdf.getKdfParameters();

    const uuid = kdf_params.get("$UUID").?;
    try std.testing.expectEqual(VariantField.Type.byte, uuid.getType());
    try std.testing.expectEqual(VariantField.Kdf.argon2d, kdf_params.getUuid().?);

    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", kdf_params.getS().?);

    try std.testing.expectEqual(@as(u64, 2), kdf_params.getI().?);

    try std.testing.expectEqual(@as(u64, 0x40000000), kdf_params.getM().?);

    try std.testing.expectEqual(@as(u32, 8), kdf_params.getP().?);

    try std.testing.expectEqual(@as(u32, 0x13), kdf_params.getV().?);
}
