const std = @import("std");
const tests = @import("tests.zig");
const cbor = @import("zbor");

const argon2 = std.crypto.pwhash.argon2;
const chacha = @import("chacha.zig");
const XChaCha20IETF = chacha.XChaCha20IETF;

// +------------------------------------------------+
// | Header                                         |
// +------------------------------------------------+

pub const cipher_suites = struct {
    const CCDB_XCHACHA20_POLY1305_ARGON2ID = "CCDB_XCHACHA20_POLY1305_ARGON2ID";

    pub fn isValid(cid: []const u8) bool {
        return std.mem.eql(u8, cid, CCDB_XCHACHA20_POLY1305_ARGON2ID);
    }
};

pub const Version = struct {
    sig: [4]u8 = "CCDB".*,
    major_version: u16 = 1,
    minor_version: u16 = 0,

    pub fn serialize(self: *const @This()) [8]u8 {
        var out: [8]u8 = .{ 'C', 'C', 'D', 'B', 0, 0, 0, 0 };

        out[4] = @as(u8, @intCast(self.major_version & 0xff));
        out[5] = @as(u8, @intCast((self.major_version >> 8) & 0xff));
        out[6] = @as(u8, @intCast(self.minor_version & 0xff));
        out[7] = @as(u8, @intCast((self.minor_version >> 8) & 0xff));

        return out;
    }
};

pub const Kdf = struct {
    I: ?u32 = null,
    M: ?u32 = null,
    P: ?u24 = null,
    S: ?[32]u8 = null,

    pub fn cborStringify(self: *const @This(), _: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "S", .value_options = .{ .slice_serialization_type = .ByteString } },
            },
        }, out);
    }
};

pub const HeaderFields = struct {
    cid: []u8,
    iv: []u8,
    kdf: Kdf,
    allocator: std.mem.Allocator,

    pub fn cborStringify(self: *const @This(), _: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "cid", .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "iv", .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
        }, out);
    }
};

pub const Header = struct {
    version: Version,
    fields: HeaderFields,

    /// Create a new header.
    ///
    /// # Arguments
    /// * `cid` - A valid cipher suite as string. Providing a invalid cipher suite will result in an error.
    /// * `kdf` - Key derivation parameters. Missing key derivation parameters will result in an error. Which parameters are required depends on the `cid`.
    /// * `random` - A cryptographically secure random number generator (CSPRNG).
    /// * `allocator` - A Allocator used to dupe the `cid` and allocate memory for the `iv`. The caller of this function owns all memory and is responsible for calling `deinit()` before dropping the object.
    pub fn new(
        cid: []const u8,
        kdf: Kdf,
        random: std.Random,
        allocator: std.mem.Allocator,
    ) !@This() {
        if (!cipher_suites.isValid(cid)) return error.InvalidCipherSuite;

        const cid_ = try allocator.dupe(u8, cid);
        errdefer allocator.free(cid_);

        const iv_ = if (std.mem.eql(u8, cid, cipher_suites.CCDB_XCHACHA20_POLY1305_ARGON2ID)) blk: {
            if (kdf.I == null or kdf.M == null or kdf.P == null) return error.MissingKdfParams;

            break :blk try allocator.alloc(u8, 24);
        } else unreachable;
        errdefer allocator.free(iv_);
        random.bytes(iv_);

        const h = Header{
            .version = .{},
            .fields = .{
                .cid = cid_,
                .iv = iv_,
                .kdf = kdf,
                .allocator = allocator,
            },
        };

        return h;
    }

    /// Free all memory allocated by the Header.
    pub fn deinit(self: *const @This()) void {
        self.fields.allocator.free(self.fields.cid);
        self.fields.allocator.free(self.fields.iv);
    }

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        // 256 bytes should be more than enough. In the future this might change
        // if new fields are added.
        if (self.fields.cid.len + self.fields.iv.len > 128) return error.UnexpectedlyLongCidOrIv;
        var buffer: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);
        var arr = std.ArrayList(u8).init(fba.allocator());

        // version
        try writer.writeAll(self.version.serialize()[0..]);

        // header fields length
        try cbor.stringify(self.fields, .{}, arr.writer());
        const l: u32 = @intCast(arr.items.len); // todo implement cbor function that calculates length
        try writer.writeAll(std.mem.toBytes(std.mem.nativeToLittle(u32, l))[0..]);

        // header fields
        try writer.writeAll(arr.items);
    }

    pub fn deserialize(raw: []const u8, allocator: std.mem.Allocator, used: ?*usize) !Header {
        if (raw.len < 12) return error.UnexpectedEndOfInput;

        if (!std.mem.eql(u8, "CCDB", raw[0..4])) return error.WrongFileFormat;
        const vmaj: u16 = @as(u16, @intCast(raw[5])) << 8 | @as(u16, @intCast(raw[4]));
        const vmin: u16 = @as(u16, @intCast(raw[7])) << 8 | @as(u16, @intCast(raw[6]));
        if (vmaj != 1 or vmin != 0) return error.UnsupportedVersion;

        const l: u32 = @as(u32, @intCast(raw[11])) << 24 | @as(u32, @intCast(raw[10])) << 16 | @as(u32, @intCast(raw[9])) << 8 | @as(u32, @intCast(raw[8]));
        if (raw.len < 12 + l) return error.UnexpectedEndOfInput;

        const di = try cbor.DataItem.new(raw[12 .. 12 + @as(usize, @intCast(l))]);
        const fields = try cbor.parse(HeaderFields, di, .{
            .allocator = allocator,
        });

        if (used != null) used.?.* = 12 + l;

        return .{
            .version = .{
                .major_version = vmaj,
                .minor_version = vmin,
            },
            .fields = fields,
        };
    }
};

// +------------------------------------------------+
// | Tests                                          |
// +------------------------------------------------+

test "serialize header" {
    const allocator = std.testing.allocator;

    const header = try Header.new(
        cipher_suites.CCDB_XCHACHA20_POLY1305_ARGON2ID,
        .{ .I = 2, .M = 19456, .P = 1 },
        std.crypto.random,
        allocator,
    );
    @memcpy(header.fields.iv, "\x50\xe1\xf0\x45\xf7\x22\x2f\x6b\xe1\xb0\xe5\xf9\x5b\x2f\x9d\xc8\x97\x29\x48\x5c\xd5\x2f\xc9\x27");
    defer header.deinit();

    var mem = std.ArrayList(u8).init(allocator);
    defer mem.deinit();

    try header.serialize(mem.writer());

    try std.testing.expectEqualSlices(u8, "CCDB\x01\x00\x00\x00\x54\x00\x00\x00\xa3\x63\x63\x69\x64\x78\x20\x43\x43\x44\x42\x5f\x58\x43\x48\x41\x43\x48\x41\x32\x30\x5f\x50\x4f\x4c\x59\x31\x33\x30\x35\x5f\x41\x52\x47\x4f\x4e\x32\x49\x44\x62\x69\x76\x58\x18\x50\xe1\xf0\x45\xf7\x22\x2f\x6b\xe1\xb0\xe5\xf9\x5b\x2f\x9d\xc8\x97\x29\x48\x5c\xd5\x2f\xc9\x27\x63\x6b\x64\x66\xa3\x61\x49\x02\x61\x4d\x19\x4c\x00\x61\x50\x01", mem.items);
}

test "deserialize header" {
    const allocator = std.testing.allocator;
    const raw = "CCDB\x01\x00\x00\x00\x54\x00\x00\x00\xa3\x63\x63\x69\x64\x78\x20\x43\x43\x44\x42\x5f\x58\x43\x48\x41\x43\x48\x41\x32\x30\x5f\x50\x4f\x4c\x59\x31\x33\x30\x35\x5f\x41\x52\x47\x4f\x4e\x32\x49\x44\x62\x69\x76\x58\x18\x50\xe1\xf0\x45\xf7\x22\x2f\x6b\xe1\xb0\xe5\xf9\x5b\x2f\x9d\xc8\x97\x29\x48\x5c\xd5\x2f\xc9\x27\x63\x6b\x64\x66\xa3\x61\x49\x02\x61\x4d\x19\x4c\x00\x61\x50\x01";
    var used: usize = 0;

    const header = try Header.deserialize(raw, allocator, &used);
    defer header.deinit();

    try std.testing.expectEqual(raw.len, used);

    try std.testing.expectEqual(@as(u32, 2), header.fields.kdf.I.?);
    try std.testing.expectEqual(@as(u32, 19456), header.fields.kdf.M.?);
    try std.testing.expectEqual(@as(u24, 1), header.fields.kdf.P.?);
    try std.testing.expectEqualSlices(u8, header.fields.cid, cipher_suites.CCDB_XCHACHA20_POLY1305_ARGON2ID);
    try std.testing.expectEqualSlices(u8, header.fields.iv, "\x50\xe1\xf0\x45\xf7\x22\x2f\x6b\xe1\xb0\xe5\xf9\x5b\x2f\x9d\xc8\x97\x29\x48\x5c\xd5\x2f\xc9\x27");
}
