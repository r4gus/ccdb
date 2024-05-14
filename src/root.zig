const root = @import("root");
const std = @import("std");
const zbor = @import("zbor");
const uuid = @import("uuid");

pub const options: Options = if (@hasDecl(root, "ccdb_options")) root.ccdb_options else .{};

pub const Options = struct {
    timestamp: fn () i64 = std.time.timestamp,
    rand: std.Random = std.crypto.random,
};

pub const Err = error{
    /// The application expected more bytes than provided
    unexpected_end_of_input,
    /// The first 4 bytes of the header are not CCDB
    invalid_signature,
    malformed_cbor,
    malformed_header,
    unknown_cipher,
    unknown_kdf,
    // Writer
    OutOfMemory,
    // Zbor
    UnsupportedItem,
    InvalidPairCount,
};

pub const Ccdb = struct {
    header: Header,
    body: Body,

    pub fn deinit(self: *const @This()) void {
        self.body.deinit();
    }

    pub fn default(
        gen: []const u8,
        name: []const u8,
        a: std.mem.Allocator,
    ) !Ccdb {
        var argon_salt: [32]u8 = undefined;
        options.rand.bytes(argon_salt[0..]);

        return .{
            .header = .{
                .fields = .{
                    .kdf = .{
                        .salt = argon_salt,
                    },
                },
            },
            .body = .{
                .meta = try Meta.new(gen, name, a),
                .entries = try a.alloc(Entry, 0),
                .allocator = a,
            },
        };
    }

    pub fn serialize(
        self: *@This(),
        out: anytype,
        key: []const u8,
        opt: struct {
            /// Specify a iv for encryption. This should be null
            /// for most cases but can be useful for testing.
            iv: ?[]const u8 = null,
        },
    ) !void {
        // We MUST generate a new IV!
        switch (self.header.fields.cid) {
            .AES256GCM => {
                if (opt.iv != null and opt.iv.?.len >= 12) {
                    @memcpy(self.header.fields.iv[0..12], opt.iv.?[0..12]);
                } else {
                    options.rand.bytes(self.header.fields.iv[0..12]);
                }
            },
        }

        // Now serialize the header...
        var header = std.ArrayList(u8).init(self.body.allocator);
        defer header.deinit();
        try self.header.encodeHeader(header.writer());

        // After the header comes the body...

        // First we have to encode the body to CBOR...
        var cbor_body = std.ArrayList(u8).init(self.body.allocator);
        errdefer cbor_body.deinit();
        try zbor.stringify(self.body, .{}, cbor_body.writer());

        //std.log.err("{s}", .{std.fmt.fmtSliceHexLower(cbor_body.items)});

        // If compression is enabled, we have to compress the body...
        var encoded_body: []const u8 = try cbor_body.toOwnedSlice();
        defer self.body.allocator.free(encoded_body);
        switch (self.header.fields.cmp) {
            .None => {},
            .Gzip => {
                var in_stream = std.io.fixedBufferStream(encoded_body);
                var compressed_body = std.ArrayList(u8).init(self.body.allocator);
                defer compressed_body.deinit();
                try std.compress.gzip.compress(
                    in_stream.reader(),
                    compressed_body.writer(),
                    .{},
                );
                const x = try compressed_body.toOwnedSlice();
                self.body.allocator.free(encoded_body);
                encoded_body = x;
            },
        }

        //std.log.err("{s}", .{std.fmt.fmtSliceHexLower(encoded_body)});

        const l: u64 = @as(u64, @intCast(encoded_body.len));
        try header.append(@as(u8, @intCast(l & 0xff)));
        try header.append(@as(u8, @intCast((l >> 8) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 16) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 24) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 32) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 40) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 48) & 0xff)));
        try header.append(@as(u8, @intCast((l >> 56) & 0xff)));

        switch (self.header.fields.cid) {
            .AES256GCM => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

                // Check that the key length is not too short.
                if (key.len < Aes256Gcm.key_length) return error.KeyLength;
                const c = try self.body.allocator.alloc(u8, encoded_body.len);
                defer self.body.allocator.free(c);
                var tag: [Aes256Gcm.tag_length]u8 = undefined;

                Aes256Gcm.encrypt(
                    c,
                    &tag,
                    encoded_body,
                    header.items,
                    self.header.fields.iv[0..12].*,
                    key[0..Aes256Gcm.key_length].*,
                );

                try out.writeAll(header.items);
                try out.writeAll(tag[0..]);
                try out.writeAll(c);
            },
        }
    }
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

    pub fn encodeHeader(self: *const @This(), writer: anytype) Err!void {
        try writer.writeAll(&self.sig);
        try writer.writeByte(@as(u8, @intCast(self.v_major & 0xff)));
        try writer.writeByte(@as(u8, @intCast(self.v_major >> 8)));
        try writer.writeByte(@as(u8, @intCast(self.v_minor & 0xff)));
        try writer.writeByte(@as(u8, @intCast(self.v_minor >> 8)));

        // Note: the buffer has been chosen to be twice as large
        // as the average header size. If more header fields are
        // added, one should also adjust the buffer size;
        var buffer: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);
        const allocator = fba.allocator();
        var al = std.ArrayList(u8).init(allocator);

        try zbor.stringify(self.fields, .{}, al.writer());

        const l = @as(u32, @intCast(al.items.len));
        try writer.writeByte(@as(u8, @intCast(l & 0xff)));
        try writer.writeByte(@as(u8, @intCast((l >> 8) & 0xff)));
        try writer.writeByte(@as(u8, @intCast((l >> 16) & 0xff)));
        try writer.writeByte(@as(u8, @intCast((l >> 24) & 0xff)));

        try writer.writeAll(al.items);
    }
};

pub const HeaderFields = struct {
    /// The cipher the database is encrypted with, encoded as integer
    /// as defined by [RFC9053] and [RFC9054].
    cid: CipherId = CipherId.AES256GCM,
    /// Initialization vector (nonce) used for encryption.
    /// The IVs size depends on the cipher used for encryption.
    iv: [32]u8 = .{0} ** 32,
    /// Compression algorithm.
    cmp: Compression = Compression.None,
    /// Values specific for the key derivation.
    kdf: KdfParams,

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.build.writeMap(out, 4);

        try zbor.build.writeTextString(out, "cid");
        try zbor.build.writeInt(out, @intFromEnum(self.cid));

        try zbor.build.writeTextString(out, "iv");
        switch (self.cid) {
            .AES256GCM => try zbor.build.writeByteString(out, self.iv[0..12]),
        }

        try zbor.build.writeTextString(out, "cmp");
        try zbor.build.writeInt(out, @intFromEnum(self.cmp));

        try zbor.build.writeTextString(out, "kdf");
        try zbor.stringify(self.kdf, .{}, out);
    }
};

pub const KdfParams = struct {
    /// The kdf to use.
    ///
    /// The default is Argon2id.
    id: [16]u8 = "\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6".*,
    /// Iterations
    iterations: ?u64 = 2, // (OWASP)
    /// Memory usage in KiB
    memory: ?u64 = 19456, // 19 MiB (OWASP)
    /// Parallelism
    parallelism: ?u32 = 1, // (OWASP)
    /// Random salt
    salt: ?[32]u8,

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
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

    pub fn cborParse(item: zbor.DataItem, _: zbor.Options) !@This() {
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
//                  Body
// ++++++++++++++++++++++++++++++++++++++++++

pub const Body = struct {
    meta: Meta,
    entries: []Entry,
    bin: ?[]Entry = null,
    allocator: std.mem.Allocator,

    pub fn updateEntry(self: *@This(), e: Entry) !void {
        for (self.entries) |*e_| {
            if (std.mem.eql(u8, &e.uuid, &e_.uuid)) {
                e_.deinit();
                e_.* = e;
            }
        } else {
            const entries_ = try self.allocator.realloc(self.entries, self.entries.len + 1);
            self.entries = entries_;
            self.entries[self.entries.len - 1] = e;
        }
        self.meta.times.update();
    }

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "meta", .field_options = .{ .alias = "0", .serialization_type = .Integer } },
                .{ .name = "entries", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "bin", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, opt: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "meta", .field_options = .{ .alias = "0", .serialization_type = .Integer } },
                .{ .name = "entries", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "bin", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = opt.allocator,
        });
    }

    pub fn new(
        gen: []const u8,
        name: []const u8,
        allocator: std.mem.Allocator,
    ) !@This() {
        return .{
            .meta = try Meta.new(gen, name, allocator),
            .entries = try allocator.alloc(Entry, 0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        self.meta.deinit();
        for (self.entries) |e| {
            e.deinit();
        }
        self.allocator.free(self.entries);
        if (self.bin) |bin| {
            for (bin) |e| {
                e.deinit();
            }
            self.allocator.free(bin);
        }
    }
};

pub const Attachment = struct {
    desc: []const u8,
    att: []const u8,
    allocator: std.mem.Allocator,

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "desc", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "att", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, opt: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "desc", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "att", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = opt.allocator,
        });
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.desc);
        self.allocator.free(self.desc);
    }
};

pub const Entry = struct {
    /// A unique identifyer for the given entry, e.g., UUIDv4 or UUIDv7.
    uuid: [36]u8,
    /// A human readable name for the given entry.
    name: []const u8,
    /// Counters and time values.
    times: Times,
    /// Notes related to the given entry.
    notes: ?[]const u8 = null,
    /// A password string.
    pw: ?[]const u8 = null,
    /// A CBOR Object Signing and Encryption (COSE) key [RFC8152].
    key: ?Key = null,
    /// A text string representing a URL.
    url: ?[]const u8 = null,
    /// The user name corresponding to the given credential.
    uname: ?[]const u8 = null,
    /// A ID assigned to the user by a relying party.
    uid: ?[]const u8 = null,
    /// A UUID referencing a Group.
    group: ?[36]u8 = null,
    /// One or more attachments associated with the given entry.
    attach: ?[]Attachment = null,
    allocator: std.mem.Allocator,

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "uuid", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "notes", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "pw", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "key", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
                .{ .name = "url", .field_options = .{ .alias = "6", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "uname", .field_options = .{ .alias = "7", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "uid", .field_options = .{ .alias = "8", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "group", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "attach", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, opt: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "uuid", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "notes", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "pw", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "key", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
                .{ .name = "url", .field_options = .{ .alias = "6", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "uname", .field_options = .{ .alias = "7", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "uid", .field_options = .{ .alias = "8", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "group", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "attach", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = opt.allocator,
        });
    }

    pub fn new(
        name: []const u8,
        /// Offset in seconds the entry should expire.
        exp: ?i64,
        allocator: std.mem.Allocator,
    ) Err!@This() {
        return .{
            .uuid = uuid.urn.serialize(uuid.v4.new2(options.rand)),
            .name = try allocator.dupe(u8, name),
            .times = Times.new(exp, null),
            .allocator = allocator,
        };
    }

    pub fn updateNotes(self: *@This(), notes: []const u8) !void {
        const new_notes = try self.allocator.dupe(u8, notes);
        if (self.notes) |old_notes| self.allocator.free(old_notes);
        self.notes = new_notes;
        self.times.update();
    }

    pub fn updatePw(self: *@This(), pw: []const u8) !void {
        const new_pw = try self.allocator.dupe(u8, pw);
        if (self.pw) |old_pw| self.allocator.free(old_pw);
        self.pw = new_pw;
        self.times.update();
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.name);

        if (self.notes) |notes| self.allocator.free(notes);
        if (self.pw) |pw| self.allocator.free(pw);
        if (self.url) |url| self.allocator.free(url);
        if (self.uname) |uname| self.allocator.free(uname);
        if (self.uid) |uid| self.allocator.free(uid);
        if (self.attach) |att| {
            for (att) |a| {
                a.deinit();
            }
            self.allocator.free(att);
        }
    }
};

pub const Times = struct {
    /// Epoch-based date/time the parent was created.
    creat: i64,
    /// Epoch-based date/time the parent was modified the last time.
    mod: i64,
    /// Epoch-based date/time the parent will expire.
    /// The meaning of this field may vary depending on the parent.
    exp: ?i64 = null,
    /// Counter how many times the parent was used.
    /// The meaning of this field may vary depending on the parent.
    cnt: ?u64 = null,

    pub fn new(
        /// Offset in seconds the parent should expire.
        exp: ?i64,
        /// Initial counter (usually 0).
        cnt: ?u64,
    ) @This() {
        return .{
            .creat = options.timestamp(),
            .mod = options.timestamp(),
            .exp = if (exp) |e| options.timestamp() + e else null,
            .cnt = cnt,
        };
    }

    pub fn update(self: *@This()) void {
        self.mod = options.timestamp();
    }

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.stringify(self.*, .{
            .field_settings = &.{
                .{ .name = "creat", .field_options = .{ .alias = "0", .serialization_type = .Integer } },
                .{ .name = "mod", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "exp", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "cnt", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            },
            .from_callback = true,
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, _: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
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

pub const Meta = struct {
    /// The name of the application that created the database.
    gen: []const u8,
    /// The name of the database.
    name: []const u8,
    /// Epoch-based date/time. This field has to be updated each time the database content is changed.
    times: Times,
    allocator: std.mem.Allocator,

    pub fn new(
        gen: []const u8,
        name: []const u8,
        allocator: std.mem.Allocator,
    ) Err!@This() {
        return .{
            .gen = try allocator.dupe(u8, gen),
            .name = try allocator.dupe(u8, name),
            .times = Times.new(null, null),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.gen);
        self.allocator.free(self.name);
    }

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        try zbor.stringify(self.*, .{
            .field_settings = &.{
                .{ .name = "gen", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .from_callback = true,
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, opt: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "gen", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = opt.allocator,
        });
    }
};

pub const Key = struct {
    /// kty: Identification of the key type
    kty: zbor.cose.KeyType = .Ec2,
    /// alg: Key usage restriction to this algorithm
    alg: zbor.cose.Algorithm,
    /// crv: EC identifier -- Taken from the "COSE Elliptic Curves" registry
    crv: zbor.cose.Curve = .P256,
    /// x: x-coordinate
    x: ?[32]u8 = null,
    /// y: y-coordinate
    y: ?[32]u8 = null,
    /// Private key
    d: ?[32]u8 = null,

    pub fn cborStringify(self: *const @This(), _: zbor.Options, out: anytype) !void {
        return zbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{
                    .name = "kty",
                    .field_options = .{
                        .alias = "1",
                        .serialization_type = .Integer,
                    },
                    .value_options = .{ .enum_serialization_type = .Integer },
                },
                .{
                    .name = "alg",
                    .field_options = .{
                        .alias = "3",
                        .serialization_type = .Integer,
                    },
                    .value_options = .{ .enum_serialization_type = .Integer },
                },
                .{
                    .name = "crv",
                    .field_options = .{
                        .alias = "-1",
                        .serialization_type = .Integer,
                    },
                    .value_options = .{ .enum_serialization_type = .Integer },
                },
                .{ .name = "x", .field_options = .{
                    .alias = "-2",
                    .serialization_type = .Integer,
                } },
                .{ .name = "y", .field_options = .{
                    .alias = "-3",
                    .serialization_type = .Integer,
                } },
                .{ .name = "d", .field_options = .{
                    .alias = "-4",
                    .serialization_type = .Integer,
                } },
            },
        }, out);
    }

    pub fn cborParse(item: zbor.DataItem, opt: zbor.Options) !@This() {
        return try zbor.parse(@This(), item, .{
            .allocator = opt.allocator,
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{
                    .name = "kty",
                    .field_options = .{
                        .alias = "1",
                        .serialization_type = .Integer,
                    },
                },
                .{
                    .name = "alg",
                    .field_options = .{
                        .alias = "3",
                        .serialization_type = .Integer,
                    },
                },
                .{
                    .name = "crv",
                    .field_options = .{
                        .alias = "-1",
                        .serialization_type = .Integer,
                    },
                },
                .{ .name = "x", .field_options = .{
                    .alias = "-2",
                    .serialization_type = .Integer,
                } },
                .{ .name = "y", .field_options = .{
                    .alias = "-3",
                    .serialization_type = .Integer,
                } },
                .{ .name = "d", .field_options = .{
                    .alias = "-4",
                    .serialization_type = .Integer,
                } },
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

test "encode header #1" {
    const h = Header{
        .v_major = 1,
        .v_minor = 0,
        .fields = .{
            .cid = CipherId.AES256GCM,
            .iv = .{ 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 } ++ .{0} ** 20,
            .cmp = Compression.Gzip,
            .kdf = .{
                .id = "\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6".*,
                .iterations = 2,
                .memory = 4096,
                .parallelism = 8,
                .salt = "\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04".*,
            },
        },
    };

    const raw_header = "\x43\x43\x44\x42\x01\x00\x00\x00\x66\x00\x00\x00\xa4\x63\x63\x69\x64\x03\x62\x69\x76\x4c\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x63\x63\x6d\x70\x01\x63\x6b\x64\x66\xa5\x65\x24\x55\x55\x49\x44\x50\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6\x61\x49\x02\x61\x4d\x19\x10\x00\x61\x50\x08\x61\x53\x58\x20\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04";

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();
    try h.encodeHeader(arr.writer());

    try std.testing.expectEqualSlices(u8, raw_header, arr.items);
}

test "create entry #1" {
    var e = try Entry.new("Github", null, std.testing.allocator);
    defer e.deinit();

    try e.updatePw("supersecret");
    try e.updateNotes("I should probably change my password.");
}

test "encode entry #1" {
    const a = std.testing.allocator;

    const expected = "\xa5\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x03\x78\x25\x49\x20\x73\x68\x6f\x75\x6c\x64\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x63\x68\x61\x6e\x67\x65\x20\x6d\x79\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x2e\x04\x6b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74";

    const e = Entry{
        .uuid = "0e695c28-42f9-43e4-9aca-3f71cd701dc0".*,
        .name = try a.dupe(u8, "Github"),
        .times = Times{
            .creat = 1714585008,
            .mod = 1714585008,
        },
        .notes = try a.dupe(u8, "I should probably change my password."),
        .pw = try a.dupe(u8, "supersecret"),
        .allocator = a,
    };
    defer e.deinit();

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();
    try zbor.stringify(e, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "decode entry #1" {
    const raw_entry = "\xa5\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x03\x78\x25\x49\x20\x73\x68\x6f\x75\x6c\x64\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x63\x68\x61\x6e\x67\x65\x20\x6d\x79\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x2e\x04\x6b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74";

    const di = try zbor.DataItem.new(raw_entry);
    const e = try zbor.parse(Entry, di, .{ .allocator = std.testing.allocator });
    defer e.deinit();

    try std.testing.expectEqualSlices(u8, "0e695c28-42f9-43e4-9aca-3f71cd701dc0", &e.uuid);
    try std.testing.expectEqualSlices(u8, "Github", e.name);
    try std.testing.expectEqual(@as(i64, 1714585008), e.times.creat);
    try std.testing.expectEqual(@as(i64, 1714585008), e.times.mod);
    try std.testing.expectEqualSlices(u8, "I should probably change my password.", e.notes.?);
    try std.testing.expectEqualSlices(u8, "supersecret", e.pw.?);
}

test "encode meta #1" {
    const a = std.testing.allocator;

    const expected = "\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6a\x4d\x79\x20\x53\x65\x63\x72\x65\x74\x73\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0";

    const e = Meta{
        .gen = try a.dupe(u8, "PassKeeZ"),
        .name = try a.dupe(u8, "My Secrets"),
        .times = Times{
            .creat = 1714585008,
            .mod = 1714585008,
        },
        .allocator = a,
    };
    defer e.deinit();

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();
    try zbor.stringify(e, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "decode meta #1" {
    const raw_entry = "\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6a\x4d\x79\x20\x53\x65\x63\x72\x65\x74\x73\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0";

    const di = try zbor.DataItem.new(raw_entry);
    const m = try zbor.parse(Meta, di, .{ .allocator = std.testing.allocator });
    defer m.deinit();

    try std.testing.expectEqualSlices(u8, "PassKeeZ", m.gen);
    try std.testing.expectEqualSlices(u8, "My Secrets", m.name);
    try std.testing.expectEqual(@as(i64, 1714585008), m.times.creat);
    try std.testing.expectEqual(@as(i64, 1714585008), m.times.mod);
}

test "encode body #1" {
    const a = std.testing.allocator;

    const expected = "\xa2\x00\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6a\x4d\x79\x20\x53\x65\x63\x72\x65\x74\x73\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x01\x82\xa5\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x03\x78\x25\x49\x20\x73\x68\x6f\x75\x6c\x64\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x63\x68\x61\x6e\x67\x65\x20\x6d\x79\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x2e\x04\x6b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\xa7\x00\x78\x24\x62\x61\x63\x39\x64\x66\x36\x35\x2d\x37\x35\x65\x34\x2d\x34\x38\x35\x66\x2d\x38\x34\x37\x63\x2d\x32\x33\x61\x32\x34\x33\x64\x39\x33\x65\x66\x32\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x05\xa4\x01\x02\x03\x26\x20\x01\x23\x58\x20\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\x65\x72\x34\x67\x75\x73\x08\x58\x20\xb5\xe3\x68\x34\xa0\xda\x97\xb7\x50\x35\x58\x54\x90\x93\xe0\x48\x59\x4b\xc5\x11\xe2\x5c\xc8\x51\xcc\xf7\xa6\x8c\xb0\xfa\xd3\xf8";

    var body = try Body.new("PassKeeZ", "My Secrets", a);
    defer body.deinit();
    body.meta.times.creat = 1714585008;

    try body.updateEntry(Entry{
        .uuid = "0e695c28-42f9-43e4-9aca-3f71cd701dc0".*,
        .name = try a.dupe(u8, "Github"),
        .times = Times{
            .creat = 1714585008,
            .mod = 1714585008,
        },
        .notes = try a.dupe(u8, "I should probably change my password."),
        .pw = try a.dupe(u8, "supersecret"),
        .allocator = a,
    });

    try body.updateEntry(Entry{
        .uuid = "bac9df65-75e4-485f-847c-23a243d93ef2".*,
        .name = try a.dupe(u8, "Github"),
        .times = Times{
            .creat = 1714585008,
            .mod = 1714585008,
        },
        .key = .{
            .alg = .Es256,
            .d = "\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d".*,
        },
        .url = try a.dupe(u8, "github.com"),
        .uname = try a.dupe(u8, "r4gus"),
        .uid = try a.dupe(u8, "\xb5\xe3\x68\x34\xa0\xda\x97\xb7\x50\x35\x58\x54\x90\x93\xe0\x48\x59\x4b\xc5\x11\xe2\x5c\xc8\x51\xcc\xf7\xa6\x8c\xb0\xfa\xd3\xf8"),
        .allocator = a,
    });
    // We have to fake this...
    body.meta.times.mod = 1714585008;

    var raw = std.ArrayList(u8).init(std.testing.allocator);
    defer raw.deinit();
    try zbor.stringify(body, .{}, raw.writer());

    try std.testing.expectEqualSlices(u8, expected, raw.items);
}

test "decode body #1" {
    const raw_body = "\xa2\x00\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6a\x4d\x79\x20\x53\x65\x63\x72\x65\x74\x73\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x01\x82\xa5\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x03\x78\x25\x49\x20\x73\x68\x6f\x75\x6c\x64\x20\x70\x72\x6f\x62\x61\x62\x6c\x79\x20\x63\x68\x61\x6e\x67\x65\x20\x6d\x79\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x2e\x04\x6b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\xa7\x00\x78\x24\x62\x61\x63\x39\x64\x66\x36\x35\x2d\x37\x35\x65\x34\x2d\x34\x38\x35\x66\x2d\x38\x34\x37\x63\x2d\x32\x33\x61\x32\x34\x33\x64\x39\x33\x65\x66\x32\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x32\x7d\xb0\x01\x1a\x66\x32\x7d\xb0\x05\xa4\x01\x02\x03\x26\x20\x01\x23\x58\x20\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\x65\x72\x34\x67\x75\x73\x08\x58\x20\xb5\xe3\x68\x34\xa0\xda\x97\xb7\x50\x35\x58\x54\x90\x93\xe0\x48\x59\x4b\xc5\x11\xe2\x5c\xc8\x51\xcc\xf7\xa6\x8c\xb0\xfa\xd3\xf8";

    const di = try zbor.DataItem.new(raw_body);
    const body = try zbor.parse(Body, di, .{ .allocator = std.testing.allocator });
    defer body.deinit();

    try std.testing.expectEqualSlices(u8, "PassKeeZ", body.meta.gen);

    try std.testing.expectEqualSlices(u8, "0e695c28-42f9-43e4-9aca-3f71cd701dc0", &body.entries[0].uuid);
    try std.testing.expectEqualSlices(u8, "Github", body.entries[0].name);
    try std.testing.expectEqualSlices(u8, "I should probably change my password.", body.entries[0].notes.?);
    try std.testing.expectEqualSlices(u8, "supersecret", body.entries[0].pw.?);

    try std.testing.expectEqualSlices(u8, "bac9df65-75e4-485f-847c-23a243d93ef2", &body.entries[1].uuid);
    try std.testing.expectEqualSlices(u8, "Github", body.entries[1].name);
    try std.testing.expectEqual(zbor.cose.KeyType.Ec2, body.entries[1].key.?.kty);
    try std.testing.expectEqual(zbor.cose.Algorithm.Es256, body.entries[1].key.?.alg);
    try std.testing.expectEqual(zbor.cose.Curve.P256, body.entries[1].key.?.crv);
    try std.testing.expectEqualSlices(u8, "\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d", &body.entries[1].key.?.d.?);
    try std.testing.expectEqualSlices(u8, "github.com", body.entries[1].url.?);
    try std.testing.expectEqualSlices(u8, "r4gus", body.entries[1].uname.?);
    try std.testing.expectEqualSlices(u8, "\xb5\xe3\x68\x34\xa0\xda\x97\xb7\x50\x35\x58\x54\x90\x93\xe0\x48\x59\x4b\xc5\x11\xe2\x5c\xc8\x51\xcc\xf7\xa6\x8c\xb0\xfa\xd3\xf8", body.entries[1].uid.?);
}

test "encode database #1" {
    const key = "\x5f\x49\xee\xd7\x7c\x3c\xa9\x9e\xea\xfe\xe5\x48\x26\xa2\x9e\x83\xdb\xe9\x44\xbf\x7a\xc8\xa2\x60\xa1\x11\x88\xed\xcf\xa7\x8c\xc2";

    const raw_header = "\x43\x43\x44\x42\x01\x00\x00\x00\x66\x00\x00\x00\xa4\x63\x63\x69\x64\x03\x62\x69\x76\x4c\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x63\x63\x6d\x70\x00\x63\x6b\x64\x66\xa5\x65\x24\x55\x55\x49\x44\x50\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6\x61\x49\x02\x61\x4d\x19\x4c\x00\x61\x50\x01\x61\x53\x58\x20\xe5\x0b\xe8\x5f\x50\x9b\xb4\xeb\x39\x2a\xf5\x06\x86\x85\x76\x4f\x94\xbb\x53\xb2\x7c\x36\x08\x06\xc7\x28\xce\x1c\x23\x80\xc3\xea";
    const tag = "\x9f\x51\xfe\x05\x3b\x11\x9b\xb6\x5b\x02\xc4\x60\x17\x8a\xf6\xad";
    const raw_body = "\xe0\x58\x7a\x41\x92\xfb\x9d\xb2\x0a\xac\xfb\x69\x2c\x60\x3f\xdf\x9e\x5f\x58\x0a\xae\x68\x76\xea\xb2\x67\x2a\xfc\x1e\x06\x81\x05\xa6\x55\x36\x31\x41\xef\x68\x16\x35\xa4";

    const expected = raw_header ++ "\x2a\x00\x00\x00\x00\x00\x00\x00" ++ tag ++ raw_body;

    var db = try Ccdb.default("PassKeeZ", "Credentials", std.testing.allocator);
    defer db.deinit();
    db.header.fields.kdf.salt = "\xe5\x0b\xe8\x5f\x50\x9b\xb4\xeb\x39\x2a\xf5\x06\x86\x85\x76\x4f\x94\xbb\x53\xb2\x7c\x36\x08\x06\xc7\x28\xce\x1c\x23\x80\xc3\xea".*;
    db.body.meta.times.creat = 1714585008;
    db.body.meta.times.mod = 1714585008;

    var raw = std.ArrayList(u8).init(std.testing.allocator);
    defer raw.deinit();

    try db.serialize(raw.writer(), key, .{ .iv = "\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04" });

    //std.log.err("{s}", .{std.fmt.fmtSliceHexLower(raw.items)});

    try std.testing.expectEqualSlices(u8, expected, raw.items);
}
