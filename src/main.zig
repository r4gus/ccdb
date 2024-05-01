const std = @import("std");

pub const CcdbErr = enum(c_int) {
    success = 0,
};

pub const Ccdb = extern struct {
    header: Header,
};

export fn decode_header(header: *Header, h: [*c]u8, len: usize) c_int {
    _ = header;
    _ = h;
    _ = len;

    return @intFromEnum(CcdbErr.success);
}

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

pub const Header = extern struct {
    sig: [4]u8 = .{ 'C', 'C', 'D', 'B' },
    v_major: u16 = 1,
    v_minor: u16 = 0,
    fields: HeaderFields,
};

pub const HeaderFields = extern struct {
    /// Initialization vector (nonce) used for encryption.
    /// The IVs size depends on the cipher used for encryption.
    iv: [16]u8 = .{0} ** 16,
    iv_len: usize,
    /// The cipher the database is encrypted with, encoded as integer
    /// as defined by [RFC9053] and [RFC9054].
    cid: i32 = CipherId.AES256GCM,
    /// Compression algorithm.
    cmp: i32 = Compression.Gzip,
    /// Values specific for the key derivation.
    kdf: KdfParams,
};

pub const KdfParams = extern struct {
    /// UUID indicating the key derivation function:
    ///
    /// - Argon2id: 9e298b19-56db-4773-b23d-fc3ec6f0a1e6
    uuid: [16]u8,
    /// Iterations
    iterations: u64 = 2,
    /// Memory usage in KiB
    memory: u64 = 19456,
    /// Parallelism
    parallelism: u32 = 1,
    /// Random salt
    salt: [32]u8,
};

// ++++++++++++++++++++++++++++++++++++++++++
//                  Tests
// ++++++++++++++++++++++++++++++++++++++++++
