const std = @import("std");
const zbor = @import("zbor");

pub const Err = error{
    /// The application expected more bytes than provided
    unexpected_end_of_input,
    /// The first 4 bytes of the header are not CCDB
    invalid_signature,
    malformed_cbor,
    malformed_header,
    unknown_cipher,
    unknown_kdf,
};

pub const Ccdb = struct {
    header: Header,
};

// ++++++++++++++++++++++++++++++++++++++++++
//                  Header
// ++++++++++++++++++++++++++++++++++++++++++

pub const CipherId = enum(i32) {
    AES256GCM = 3,
};

pub const Compression = enum(i32) {
    None = 0,
    Gzip = 1,
};

pub const Header = struct {
    sig: [4]u8 = .{ 'C', 'C', 'D', 'B' },
    v_major: u16 = 1,
    v_minor: u16 = 0,
    fields: HeaderFields,

    pub fn decodeHeader(raw: []const u8) Err!Header {
        if (raw.len < 12) return Err.unexpected_end_of_input;
        if (!std.mem.eql(u8, raw[0..4], "CCDB")) return Err.invalid_signature;

        var header = Header{
            .v_major = std.mem.readInt(u16, raw[4..6], .little),
            .v_minor = std.mem.readInt(u16, raw[6..8], .little),
            .fields = undefined,
        };

        const l: usize = std.mem.readInt(u32, raw[8..12], .little);
        if (raw.len < l + 12) return Err.unexpected_end_of_input;

        const di = zbor.DataItem.new(raw[12 .. 12 + l]) catch {
            return Err.malformed_cbor;
        };
        header.fields = zbor.parse(HeaderFields, di, .{}) catch {
            return Err.malformed_header;
        };

        return header;
    }
};

pub const HeaderFields = struct {
    /// The cipher the database is encrypted with, encoded as integer
    /// as defined by [RFC9053] and [RFC9054].
    cid: CipherId = CipherId.AES256GCM,
    /// Initialization vector (nonce) used for encryption.
    /// The IVs size depends on the cipher used for encryption.
    iv: [16]u8 = .{0} ** 16,
    /// Compression algorithm.
    cmp: Compression = Compression.Gzip,
    /// Values specific for the key derivation.
    kdf: KdfParams,
};

pub const KdfParams = struct {
    id: [16]u8,
    /// Iterations
    iterations: ?u64,
    /// Memory usage in KiB
    memory: ?u64,
    /// Parallelism
    parallelism: ?u32,
    /// Random salt
    salt: ?[32]u8,

    pub fn cborStringify(self: *const @This(), options: zbor.Options, out: anytype) !void {
        _ = options;
        try zbor.stringify(self.*, .{
            .field_settings = &.{
                .{ .name = "id", .field_options = .{ .alias = "$UUID" } },
                .{ .name = "iterations", .field_options = .{ .alias = "I" } },
                .{ .name = "memory", .field_options = .{ .alias = "M" } },
                .{ .name = "parallelism", .field_options = .{ .alias = "P" } },
                .{ .name = "salt", .field_options = .{ .alias = "S" } },
            },
            .from_callback = true,
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, options: zbor.Options) !@This() {
        _ = options;
        return try zbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "id", .field_options = .{ .alias = "$UUID" } },
                .{ .name = "iterations", .field_options = .{ .alias = "I" } },
                .{ .name = "memory", .field_options = .{ .alias = "M" } },
                .{ .name = "parallelism", .field_options = .{ .alias = "P" } },
                .{ .name = "salt", .field_options = .{ .alias = "S" } },
            },
        });
    }
};

// ++++++++++++++++++++++++++++++++++++++++++
//                  Tests
// ++++++++++++++++++++++++++++++++++++++++++

test "parse header #1" {
    const raw_header = "\x43\x43\x44\x42\x01\x00\x00\x00\x66\x00\x00\x00\xa4\x62\x69\x76\x4c\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x63\x63\x69\x64\x03\x63\x63\x6d\x70\x01\x63\x6b\x64\x66\xa5\x65\x24\x55\x55\x49\x44\x50\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6\x61\x49\x02\x61\x4d\x19\x10\x00\x61\x50\x08\x61\x53\x58\x20\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04";

    const h = try Header.decodeHeader(raw_header);

    try std.testing.expectEqual(@as(u16, 1), h.v_major);
    try std.testing.expectEqual(@as(u16, 0), h.v_minor);
    try std.testing.expectEqual(CipherId.AES256GCM, h.fields.cid);
    try std.testing.expectEqualSlices(u8, "\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04", h.fields.iv[0..12]);
    try std.testing.expectEqual(Compression.Gzip, h.fields.cmp);
    try std.testing.expectEqualSlices(u8, "\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6", &h.fields.kdf.id);
    try std.testing.expectEqual(@as(u64, 2), h.fields.kdf.iterations.?);
    try std.testing.expectEqual(@as(u64, 4096), h.fields.kdf.memory.?);
    try std.testing.expectEqual(@as(u32, 8), h.fields.kdf.parallelism.?);
    try std.testing.expectEqualSlices(u8, "\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04", &h.fields.kdf.salt.?);
}
