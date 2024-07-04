const std = @import("std");
const tests = @import("tests.zig");
const cbor = @import("zbor");
const uuid = @import("uuid");

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

    pub fn deriveKey(self: *const @This(), key: []u8, key_data: []const u8, allocator: std.mem.Allocator) !void {
        if (std.mem.eql(u8, cipher_suites.CCDB_XCHACHA20_POLY1305_ARGON2ID, self.fields.cid)) {
            if (self.fields.kdf.I == null or self.fields.kdf.M == null or self.fields.kdf.P == null or self.fields.kdf.S == null) return error.MissingKdfParams;

            try argon2.kdf(allocator, key, key_data, self.fields.kdf.S.?[0..], .{
                .t = self.fields.kdf.I.?,
                .m = self.fields.kdf.M.?,
                .p = self.fields.kdf.P.?,
            }, .argon2id);
        } else return error.InvalidCipherSuite; // This is bad is it should have been captured much earlier :(
    }
};

// +------------------------------------------------+
// | Body                                           |
// +------------------------------------------------+

pub const Times = struct {
    creat: i64,
    mod: i64,
    exp: ?i64 = null,
    cnt: ?usize = null,

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

pub const Meta = struct {
    gen: []u8,
    name: []u8,
    times: Times,
    allocator: std.mem.Allocator,

    pub fn new(gen: []const u8, name: []const u8, allocator: std.mem.Allocator, milliTimestamp: fn () i64) !@This() {
        const gen_ = try allocator.dupe(u8, gen);
        errdefer allocator.free(gen_);
        const name_ = try allocator.dupe(u8, name);
        const t = milliTimestamp();

        return .{
            .gen = gen_,
            .name = name_,
            .times = .{
                .creat = t,
                .mod = t,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.gen);
        self.allocator.free(self.name);
    }

    pub fn updateTime(self: *@This(), milliTimestamp: fn () i64) void {
        self.times.mod = milliTimestamp();
    }

    pub fn cborStringify(self: *const @This(), o: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "gen", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, o: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "gen", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        });
    }
};

pub const Entry = struct {
    /// A unique identifier for the given entry, e.g., UUIDv4 or UUIDv7, encoded as URN.
    uuid: [36]u8,
    /// A human readable name for the given entry.
    name: ?[]u8 = null,
    /// Counters and time values.
    times: Times,
    /// Notes related to the given entry.
    notes: ?[]u8 = null,
    /// A secret. This can be anything.
    secret: ?[]u8 = null,
    /// A key encoded using the CBOR Object Signing and Encryption (COSE) format.
    key: ?cbor.cose.Key = null,
    /// A text representing a (base-)URL.
    url: ?[]u8 = null,
    /// The user corresponding to the given credential.
    user: ?User = null,
    /// A URN referencing a Group.
    group: ?[36]u8 = null,
    /// One or more tags associated with the given entry.
    tags: ?[][]u8 = null,
    /// One or more attachments associated with the given entry.
    /// This can for example be a file containing recovery keys.
    attach: ?[]Attachment = null,
    allocator: std.mem.Allocator,

    pub fn new(allocator: std.mem.Allocator, milliTimestamp: fn () i64, random: std.Random) @This() {
        const id = uuid.v4.new2(random);
        const t = milliTimestamp();
        return .{
            .uuid = uuid.urn.serialize(id),
            .times = .{
                .creat = t,
                .mod = t,
            },
            .allocator = allocator,
        };
    }

    /// Assign the value `name` to the given Entry.
    ///
    /// The Entry will create a copy of `name`, i.e., the caller still owns
    /// the memory of `name` after this call. Passing `null` as an argument
    /// will free the memory allocated for the name field of the Entry.
    pub fn setName(self: *@This(), name: ?[]const u8, ms: fn () i64) !void {
        const name_: ?[]u8 = if (name) |n| try self.allocator.dupe(u8, n) else null;
        if (self.name) |n| {
            @memset(n, 0);
            self.allocator.free(n);
        }
        self.name = name_;
        self.times.mod = ms();
    }

    /// Assign the value `notes` to the given Entry.
    ///
    /// The Entry will create a copy of `notes`, i.e., the caller still owns
    /// the memory of `notes` after this call. Passing `null` as an argument
    /// will free the memory allocated for the notes field of the Entry.
    pub fn setNotes(self: *@This(), notes: ?[]const u8, ms: fn () i64) !void {
        const notes_: ?[]u8 = if (notes) |n| try self.allocator.dupe(u8, n) else null;
        if (self.notes) |n| {
            @memset(n, 0);
            self.allocator.free(n);
        }
        self.notes = notes_;
        self.times.mod = ms();
    }

    /// Assign the value `secret` to the given Entry.
    ///
    /// The Entry will create a copy of `secret`, i.e., the caller still owns
    /// the memory of `secret` after this call. Passing `null` as an argument
    /// will free the memory allocated for the secret field of the Entry.
    ///
    /// Note: If you want a second layer of encryption similar to how KDBX4 manages memory
    /// you can encrypt your secret before storing it in the secret field. In a thread
    /// modell where an attacker has access to the memory of a process this doesn't
    /// make much sense as the attacker would have access to ALL memory but you
    /// can still do it (it doesn't hurt). One thing you have to keep in mind is
    /// that the application MUST prevent the memory form being swapped out.
    pub fn setSecret(self: *@This(), secret: ?[]const u8, ms: fn () i64) !void {
        const secret_: ?[]u8 = if (secret) |s| try self.allocator.dupe(u8, s) else null;
        if (self.secret) |s| {
            @memset(s, 0);
            self.allocator.free(s);
        }
        self.secret = secret_;
        self.times.mod = ms();
    }

    /// Assign the value `url` to the given Entry.
    ///
    /// The `url` can be a full url or a base url based on your requirement.
    ///
    /// The Entry will create a copy of `url`, i.e., the caller still owns
    /// the memory of `url` after this call. Passing `null` as an argument
    /// will free the memory allocated for the url field of the Entry.
    pub fn setUrl(self: *@This(), url: ?[]const u8, ms: fn () i64) !void {
        const url_: ?[]u8 = if (url) |u| try self.allocator.dupe(u8, u) else null;
        if (self.url) |u| {
            @memset(u, 0);
            self.allocator.free(u);
        }
        self.url = url_;
        self.times.mod = ms();
    }

    /// Assign the value `user` to the given Entry.
    ///
    /// The Entry will create a copy of all fields of `user`, i.e., the caller
    /// still owns the memory of `user` after this call. Passing `null` as an argument
    /// will free the memory allocated for the user field of the Entry.
    pub fn setUser(
        self: *@This(),
        user: ?struct {
            id: ?[]const u8,
            name: ?[]const u8,
            display_name: ?[]const u8,
        },
        ms: fn () i64,
    ) !void {
        const user_: ?User = if (user) |u| blk: {
            const id_: ?[]u8 = if (u.id) |id| try self.allocator.dupe(u8, id) else null;
            errdefer if (id_ != null) self.allocator.free(id_.?);
            const name_: ?[]u8 = if (u.name) |name| try self.allocator.dupe(u8, name) else null;
            errdefer if (name_ != null) self.allocator.free(name_.?);
            const display_name_: ?[]u8 = if (u.display_name) |dn| try self.allocator.dupe(u8, dn) else null;
            break :blk User{
                .id = id_,
                .name = name_,
                .display_name = display_name_,
                .allocator = if (self.user) |u_| u_.allocator else self.allocator,
            };
        } else null;
        if (self.user) |u| u.deinit();
        self.user = user_;
        self.times.mod = ms();
    }

    pub fn addTag(self: *@This(), tag: []const u8, ms: fn () i64) !void {
        // Check if tag already exists
        if (self.tags) |tags| {
            for (tags) |tag_other| {
                if (std.mem.eql(u8, tag_other, tag)) return;
            }
        }

        var arr: std.ArrayList([]u8) = if (self.tags) |tags|
            std.ArrayList([]u8).fromOwnedSlice(self.allocator, tags)
        else
            std.ArrayList([]u8).init(self.allocator);

        const t = try self.allocator.dupe(u8, tag);
        errdefer self.allocator.free(t);

        try arr.append(t);
        self.tags = try arr.toOwnedSlice();

        self.times.mod = ms();
    }

    pub fn deinit(self: *@This()) void {
        @memset(self.uuid[0..], 0);
        if (self.name) |name| {
            @memset(name, 0);
            self.allocator.free(name);
        }
        if (self.notes) |notes| {
            @memset(notes, 0);
            self.allocator.free(notes);
        }
        if (self.secret) |secret| {
            @memset(secret, 0);
            self.allocator.free(secret);
        }
        if (self.url) |url| {
            @memset(url, 0);
            self.allocator.free(url);
        }
        if (self.user) |user| user.deinit();
        if (self.group) |*group| {
            @memset(group[0..], 0);
        }
        if (self.tags) |tags| {
            for (tags) |tag| {
                @memset(tag, 0);
                self.allocator.free(tag);
            }
            self.allocator.free(tags);
        }
        if (self.attach) |attach| {
            for (attach) |a| a.deinit();
            self.allocator.free(attach);
        }
    }

    pub fn cborStringify(self: *const @This(), o: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "uuid", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "notes", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "secret", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "key", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
                .{ .name = "url", .field_options = .{ .alias = "6", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "user", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
                .{ .name = "group", .field_options = .{ .alias = "8", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "tags", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "attach", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, o: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "uuid", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "notes", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "secret", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "key", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
                .{ .name = "url", .field_options = .{ .alias = "6", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "user", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
                .{ .name = "group", .field_options = .{ .alias = "8", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "tags", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "attach", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        });
    }
};

pub const User = struct {
    /// The user handle of the user account. A user handle is an opaque byte
    /// sequence with a maximum size of 64 bytes, and is not meant to be
    /// displayed to the user.
    id: ?[]u8 = null,
    /// A human-palatable identifier for a user account. This name is usually
    /// chosen by the user, e.g., the user name. For example, "alexm",
    /// "alex.mueller@example.com".
    name: ?[]u8 = null,
    /// A human-palatable name for the user account, intended only for display.
    /// For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let
    /// the user choose this, and SHOULD NOT restrict the choice more than necessary.
    display_name: ?[]u8 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const @This()) void {
        if (self.id) |id| self.allocator.free(id);
        if (self.name) |name| self.allocator.free(name);
        if (self.display_name) |name| self.allocator.free(name);
    }

    pub fn cborStringify(self: *const @This(), o: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "id", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "display_name", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, o: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "id", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "display_name", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        });
    }
};

pub const Attachment = struct {
    desc: []u8,
    att: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.desc);
        self.allocator.free(self.att);
    }

    pub fn cborStringify(self: *const @This(), o: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "desc", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "att", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, o: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .from_callback = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "desc", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "att", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .ByteString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        });
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

test "derive key" {
    const allocator = std.testing.allocator;

    const header = try Header.new(
        cipher_suites.CCDB_XCHACHA20_POLY1305_ARGON2ID,
        .{
            .I = 2,
            .M = 19456,
            .P = 1,
            .S = "\x7a\x03\x29\xda\xfd\x46\x6e\x07\x38\x79\x1c\xe4\x87\xf4\x41\x7a\xaf\xf4\x5a\xe0\xcb\x41\xa0\xa1\x0a\x23\xf0\x17\x15\x75\x81\xd0".*,
        },
        std.crypto.random,
        allocator,
    );
    @memcpy(header.fields.iv, "\x50\xe1\xf0\x45\xf7\x22\x2f\x6b\xe1\xb0\xe5\xf9\x5b\x2f\x9d\xc8\x97\x29\x48\x5c\xd5\x2f\xc9\x27");
    defer header.deinit();

    var out: [32]u8 = .{0} ** 32;
    try header.deriveKey(&out, "supersecret", allocator);

    // TODO: verify!
    try std.testing.expectEqualSlices(u8, "\xb1\xcf\x52\x14\x9f\x94\x0a\xac\xb9\xa9\xfd\x46\x63\xf5\xf8\x9c\xde\x43\x43\xe5\x2e\x82\xef\xcd\x47\xc1\x9b\x9c\x83\xc4\x57\x08", &out);
}

test "serialize Meta" {
    const mockup = struct {
        pub fn ms() i64 {
            return 1720033910;
        }
    };

    const allocator = std.testing.allocator;
    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    const meta = try Meta.new("PassKeeZ", "My Passkeys", allocator, mockup.ms);
    defer meta.deinit();

    try cbor.stringify(meta, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, "\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6b\x4d\x79\x20\x50\x61\x73\x73\x6b\x65\x79\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76", arr.items);
}

test "serialize Entry" {
    const mockup = struct {
        pub fn ms() i64 {
            return 1720033910;
        }
    };

    const allocator = std.testing.allocator;

    var e1 = Entry.new(
        allocator,
        mockup.ms,
        std.crypto.random,
    );
    defer e1.deinit();
    @memcpy(e1.uuid[0..], "0e695c28-42f9-43e4-9aca-3f71cd701dc0");

    try e1.setName("Bundeswehr", mockup.ms);
    try e1.setNotes("They will call me back next week.", mockup.ms);
    try e1.setSecret("supersecret", mockup.ms);
    try e1.setUrl("github.com", mockup.ms);
    try e1.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1",
        .name = "r4gus",
        .display_name = "David Sugar",
    }, mockup.ms);
    try e1.addTag("work", mockup.ms);
    try e1.addTag("VIP", mockup.ms);

    const expected = "\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50";

    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    try cbor.stringify(e1, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "deserialize Entry" {
    const allocator = std.testing.allocator;
    const raw = "\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50";

    var e1 = try cbor.parse(Entry, try cbor.DataItem.new(raw), .{ .allocator = allocator });
    defer e1.deinit();

    try std.testing.expectEqualStrings("0e695c28-42f9-43e4-9aca-3f71cd701dc0", e1.uuid[0..]);
}
