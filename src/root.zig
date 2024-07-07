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

/// The database body containing all data.
///
/// A Body should only be created by using either the `new()` or `deserialize()` function.
/// References to `self` are considered to be pointers to a Body object on the stack. A Body
/// MUST NOT be copied manually!
pub const Body = struct {
    meta: Meta,
    entries: std.ArrayList(Entry),
    groups: ?std.ArrayList(Group) = null,
    bin: ?std.ArrayList(Entry) = null,
    allocator: std.mem.Allocator,
    ms: *const fn () i64,
    rand: std.Random,

    pub fn new(gen: []const u8, name: []const u8, allocator: std.mem.Allocator, ms: *const fn () i64, rand: std.Random) !*@This() {
        const body = try allocator.create(Body);
        body.* = .{
            .meta = try Meta.new(gen, name, allocator, ms),
            .entries = std.ArrayList(Entry).init(allocator),
            .allocator = allocator,
            .ms = ms,
            .rand = rand,
        };
        return body;
    }

    pub fn deinit(self: *const @This()) void {
        self.meta.deinit();
        for (self.entries.items) |*entry| {
            entry.deinit();
        }
        self.entries.deinit();
        if (self.groups) |groups| {
            for (groups.items) |item| {
                item.deinit();
            }
            groups.deinit();
        }
        if (self.bin) |bin| {
            for (bin.items) |*item| {
                item.deinit();
            }
            bin.deinit();
        }
    }

    /// Create a new entry and add it to the list of existing entries.
    ///
    /// This function will return a pointer to the created entry, which can
    /// be used to modify the entry, e.g., add a password.
    ///
    /// The Body owns the memory. The caller MAY modify the entry using
    /// one of the provided setter functions. The caller MUST NOT modify
    /// the memory of the returned entry directly.
    pub fn newEntry(self: *@This()) !*Entry {
        var e = Entry.new(self.allocator, self.ms, self.rand);
        e.parent = @intFromPtr(self);
        try self.entries.append(e);
        return &self.entries.items[self.entries.items.len - 1];
    }

    /// Create a new group and add it to the list of existing groups.
    ///
    /// This function will return a pointer to the created group, which can
    /// be used to modify the group.
    ///
    /// The Body owns the memory. The caller MAY modify the group using
    /// one of the provided setter functions. The caller MUST NOT modify
    /// the memory of the returned group directly.
    pub fn newGroup(self: *@This(), name: []const u8) !*Group {
        const g = try Group.new(name, self.allocator, self.ms, self.rand);
        if (self.groups == null) self.groups = std.ArrayList(Group).init(self.allocator);
        try self.groups.?.append(g);
        return &self.groups.?.items[self.groups.?.items.len - 1];
    }

    /// Get the database entry with the given id.
    ///
    /// The id is a UUID encoded as URN.
    ///
    /// The Body owns the memory. The caller MAY modify the entry using
    /// one of the provided setter functions. The caller MUST NOT modify
    /// the memory of the returned entry directly.
    pub fn getEntryById(self: *const @This(), id: uuid.urn.Urn) ?*Entry {
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.uuid[0..], id[0..])) return entry;
        }
        return null;
    }

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        var l: u64 = 2;
        if (self.groups != null) l += 1;
        if (self.bin != null) l += 1;

        try cbor.build.writeMap(writer, l);
        try cbor.build.writeInt(writer, 0);
        try cbor.stringify(self.meta, .{}, writer);
        try cbor.build.writeInt(writer, 1);
        try cbor.stringify(self.entries.items, .{}, writer);
        if (self.groups) |groups| {
            try cbor.build.writeInt(writer, 2);
            try cbor.stringify(groups.items, .{}, writer);
        }
        if (self.bin) |bin| {
            try cbor.build.writeInt(writer, 3);
            try cbor.stringify(bin.items, .{}, writer);
        }
    }

    pub fn deserialize(allocator: std.mem.Allocator, ms: *const fn () i64, rand: std.Random, raw: []const u8) !*@This() {
        var di = try cbor.DataItem.new(raw);

        if (di.getType() != .Map) return error.ExpectedMap;
        var mi = di.map();
        if (mi == null) return error.ExpectedMap;

        const meta = mi.?.next();
        if (meta == null) return error.ExpectedMetaData;
        const meta_num = meta.?.key.int();
        if (meta_num == null or meta_num.? != 0) return error.MetaKeyMalformed;
        const meta_ = try cbor.parse(Meta, meta.?.value, .{ .allocator = allocator });
        errdefer meta_.deinit();

        const entries = mi.?.next();
        if (entries == null) return error.ExpectedEntries;
        const entries_num = entries.?.key.int();
        if (entries_num == null or entries_num.? != 1) return error.EntriesKeyMalformed;
        const entries_ = try cbor.parse([]Entry, entries.?.value, .{ .allocator = allocator });
        errdefer {
            for (entries_) |*entry| {
                entry.deinit();
            }
            allocator.free(entries_);
        }

        // TODO: parse remaining fields

        const body = try allocator.create(Body);
        body.* = .{
            .meta = meta_,
            .entries = std.ArrayList(Entry).fromOwnedSlice(allocator, entries_),
            .allocator = allocator,
            .ms = ms,
            .rand = rand,
        };
        for (body.entries.items) |*entry| {
            entry.parent = @intFromPtr(body);
        }

        return body;
    }
};

pub const Group = struct {
    uuid: uuid.urn.Urn,
    name: []u8,
    times: Times,
    groups: ?[]uuid.urn.Urn = null,
    entries: ?[]uuid.urn.Urn = null,
    group: ?uuid.urn.Urn = null,
    allocator: std.mem.Allocator,

    pub fn new(name: []const u8, allocator: std.mem.Allocator, milliTimestamp: *const fn () i64, random: std.Random) !@This() {
        const name_ = try allocator.dupe(u8, name);

        const id = uuid.v7.new2(random, milliTimestamp);
        const t = milliTimestamp();
        return .{
            .uuid = uuid.urn.serialize(id),
            .name = name_,
            .times = .{
                .creat = t,
                .mod = t,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.name);
        if (self.groups) |groups| self.allocator.free(groups);
        if (self.entries) |entries| self.allocator.free(entries);
    }

    pub fn addEntry(self: *@This(), entry: *Entry) !void {
        if (entry.group) |group| outer_blk: {
            if (std.mem.eql(u8, group[0..], self.uuid[0..])) return;

            if (entry.parent) |parent_| {
                const parent: *Body = @ptrFromInt(parent_);
                if (parent.groups) |groups| {
                    var i: usize = 0;
                    while (i < groups.items.len) : (i += 1) {
                        if (std.mem.eql(u8, group[0..], groups.items[i].uuid[0..])) {
                            if (groups.items[i].entries) |*entries| {
                                var e = std.ArrayList(uuid.urn.Urn).fromOwnedSlice(groups.items[i].allocator, entries.*);
                                var j: usize = 0;
                                while (j < e.items.len) : (j += 1) {
                                    if (std.mem.eql(u8, e.items[j][0..], entry.uuid[0..])) {
                                        _ = e.swapRemove(j);
                                        entries.* = try e.toOwnedSlice();
                                        break :outer_blk;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        var arr = if (self.entries) |entries| std.ArrayList(uuid.urn.Urn).fromOwnedSlice(self.allocator, entries) else std.ArrayList(uuid.urn.Urn).init(self.allocator);
        try arr.append(entry.uuid);
        self.entries = try arr.toOwnedSlice();
        entry.group = self.uuid;
    }

    pub fn addGroup(self: *@This(), group: *Group) !void {
        if (group.group != null and std.mem.eql(u8, group.group.?[0..], self.uuid[0..])) return;
        var arr = if (self.groups) |groups| std.ArrayList(uuid.urn.Urn).fromOwnedSlice(self.allocator, groups) else std.ArrayList(uuid.urn.Urn).init(self.allocator);
        try arr.append(group.uuid);
        self.groups = try arr.toOwnedSlice();
        group.group = self.uuid;
    }

    pub fn cborStringify(self: *const @This(), o: cbor.Options, out: anytype) !void {
        try cbor.stringify(self, .{
            .from_callback = true,
            .field_settings = &.{
                .{ .name = "uuid", .field_options = .{ .alias = "0", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "name", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "times", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "groups", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "entries", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "group", .field_options = .{ .alias = "5", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
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
                .{ .name = "groups", .field_options = .{ .alias = "3", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "entries", .field_options = .{ .alias = "4", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "group", .field_options = .{ .alias = "5", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
                .{ .name = "allocator", .field_options = .{ .skip = .Skip } },
            },
            .allocator = o.allocator,
        });
    }
};

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

    pub fn new(gen: []const u8, name: []const u8, allocator: std.mem.Allocator, milliTimestamp: *const fn () i64) !@This() {
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

    pub fn updateTime(self: *@This(), milliTimestamp: *const fn () i64) void {
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
    uuid: uuid.urn.Urn,
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
    group: ?uuid.urn.Urn = null,
    /// One or more tags associated with the given entry.
    tags: ?[][]u8 = null,
    /// One or more attachments associated with the given entry.
    /// This can for example be a file containing recovery keys.
    attach: ?[]Attachment = null,
    allocator: std.mem.Allocator,
    // This is a little hack to satisfy the compiler. If we use a pointer the
    // cbor parser thinks that there is a possibility that we want to include
    // the parent but the parent has some fields that can't be serialized to
    // cbor. This usize is actually a pointer but it will never be serialized!
    parent: ?usize = null,

    pub fn new(allocator: std.mem.Allocator, milliTimestamp: *const fn () i64, random: std.Random) @This() {
        const id = uuid.v7.new2(random, milliTimestamp);
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

    fn updateTime(self: *@This()) void {
        if (self.parent) |parent| {
            const p = @as(*const Body, @ptrFromInt(parent));
            self.times.mod = p.ms();
        }
    }

    /// Assign the value `name` to the given Entry.
    ///
    /// The Entry will create a copy of `name`, i.e., the caller still owns
    /// the memory of `name` after this call. Passing `null` as an argument
    /// will free the memory allocated for the name field of the Entry.
    pub fn setName(self: *@This(), name: ?[]const u8) !void {
        const name_: ?[]u8 = if (name) |n| try self.allocator.dupe(u8, n) else null;
        if (self.name) |n| {
            @memset(n, 0);
            self.allocator.free(n);
        }
        self.name = name_;
        self.updateTime();
    }

    /// Assign the value `notes` to the given Entry.
    ///
    /// The Entry will create a copy of `notes`, i.e., the caller still owns
    /// the memory of `notes` after this call. Passing `null` as an argument
    /// will free the memory allocated for the notes field of the Entry.
    pub fn setNotes(self: *@This(), notes: ?[]const u8) !void {
        const notes_: ?[]u8 = if (notes) |n| try self.allocator.dupe(u8, n) else null;
        if (self.notes) |n| {
            @memset(n, 0);
            self.allocator.free(n);
        }
        self.notes = notes_;
        self.updateTime();
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
    pub fn setSecret(self: *@This(), secret: ?[]const u8) !void {
        const secret_: ?[]u8 = if (secret) |s| try self.allocator.dupe(u8, s) else null;
        if (self.secret) |s| {
            @memset(s, 0);
            self.allocator.free(s);
        }
        self.secret = secret_;
        self.updateTime();
    }

    pub fn setKey(self: *@This(), key: ?cbor.cose.Key) void {
        self.key = key;
        self.updateTime();
    }

    /// Assign the value `url` to the given Entry.
    ///
    /// The `url` can be a full url or a base url based on your requirement.
    ///
    /// The Entry will create a copy of `url`, i.e., the caller still owns
    /// the memory of `url` after this call. Passing `null` as an argument
    /// will free the memory allocated for the url field of the Entry.
    pub fn setUrl(self: *@This(), url: ?[]const u8) !void {
        const url_: ?[]u8 = if (url) |u| try self.allocator.dupe(u8, u) else null;
        if (self.url) |u| {
            @memset(u, 0);
            self.allocator.free(u);
        }
        self.url = url_;
        self.updateTime();
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
        self.updateTime();
    }

    pub fn addTag(self: *@This(), tag: []const u8) !void {
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

        self.updateTime();
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
                .{ .name = "parent", .field_options = .{ .skip = .Skip } },
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
                .{ .name = "parent", .field_options = .{ .skip = .Skip } },
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

    try e1.setName("Bundeswehr");
    try e1.setNotes("They will call me back next week.");
    try e1.setSecret("supersecret");
    try e1.setUrl("github.com");
    try e1.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    try e1.addTag("work");
    try e1.addTag("VIP");

    const expected = "\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50";

    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    try cbor.stringify(e1, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "deserialize Entry" {
    const allocator = std.testing.allocator;
    // {0: "0e695c28-42f9-43e4-9aca-3f71cd701dc0", 1: "Bundeswehr", 2: {0: 1720033910, 1: 1720033910}, 3: "They will call me back next week.", 4: h'7375706572736563726574', 6: "github.com", 7: {0: h'B39DE50BC1080EB796F09FEE8E30C7F1', 1: "r4gus", 2: "David Sugar"}, 9: ["work", "VIP"]}
    const raw = "\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50";

    var e1 = try cbor.parse(Entry, try cbor.DataItem.new(raw), .{ .allocator = allocator });
    defer e1.deinit();

    try std.testing.expectEqualStrings("0e695c28-42f9-43e4-9aca-3f71cd701dc0", e1.uuid[0..]);
    try std.testing.expectEqualStrings("Bundeswehr", e1.name.?);
    try std.testing.expectEqualStrings("They will call me back next week.", e1.notes.?);
    try std.testing.expectEqualStrings("supersecret", e1.secret.?);
    try std.testing.expectEqualStrings("github.com", e1.url.?);
    try std.testing.expectEqualSlices(u8, "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1", e1.user.?.id.?);
    try std.testing.expectEqualSlices(u8, "r4gus", e1.user.?.name.?);
    try std.testing.expectEqualSlices(u8, "David Sugar", e1.user.?.display_name.?);
    try std.testing.expectEqualSlices(u8, "work", e1.tags.?[0]);
    try std.testing.expectEqualSlices(u8, "VIP", e1.tags.?[1]);
}

test "serialize body #1" {
    const mockup = struct {
        pub fn ms() i64 {
            return 1720033910;
        }
    };
    const allocator = std.testing.allocator;
    const raw = "\xa2\x00\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6b\x4d\x79\x20\x50\x61\x73\x73\x6b\x65\x79\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x01\x82\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50\xa7\x00\x78\x24\x32\x38\x64\x38\x34\x33\x31\x35\x2d\x34\x66\x36\x38\x2d\x34\x38\x31\x66\x2d\x62\x63\x32\x36\x2d\x36\x63\x34\x34\x63\x35\x32\x65\x30\x30\x33\x38\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x04\x48\x31\x32\x33\x34\x35\x36\x37\x38\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x81\x63\x64\x65\x76";

    var body = try Body.new("PassKeeZ", "My Passkeys", allocator, mockup.ms, std.crypto.random);
    defer {
        body.deinit();
        allocator.destroy(body);
    }

    var e1 = try body.newEntry();
    @memcpy(e1.uuid[0..], "0e695c28-42f9-43e4-9aca-3f71cd701dc0"); // so we have reproducible results
    try e1.setName("Bundeswehr");
    try e1.setNotes("They will call me back next week.");
    try e1.setSecret("supersecret");
    try e1.setUrl("github.com");
    try e1.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    try e1.addTag("work");
    try e1.addTag("VIP");

    var e2 = try body.newEntry();
    @memcpy(e2.uuid[0..], "28d84315-4f68-481f-bc26-6c44c52e0038"); // so we have reproducible results
    try e2.setName("Github");
    try e2.setSecret("12345678");
    try e2.setUrl("github.com");
    try e2.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    try e2.addTag("dev");

    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    try body.serialize(arr.writer());

    try std.testing.expectEqualSlices(u8, raw, arr.items);
}

test "deserialize body #1" {
    const mockup = struct {
        pub fn ms() i64 {
            return 1720033910;
        }
    };
    const allocator = std.testing.allocator;
    const raw = "\xa2\x00\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6b\x4d\x79\x20\x50\x61\x73\x73\x6b\x65\x79\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x01\x82\xa8\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50\xa7\x00\x78\x24\x32\x38\x64\x38\x34\x33\x31\x35\x2d\x34\x66\x36\x38\x2d\x34\x38\x31\x66\x2d\x62\x63\x32\x36\x2d\x36\x63\x34\x34\x63\x35\x32\x65\x30\x30\x33\x38\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x04\x48\x31\x32\x33\x34\x35\x36\x37\x38\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x09\x81\x63\x64\x65\x76";

    var body = try Body.deserialize(allocator, mockup.ms, std.crypto.random, raw);
    defer {
        body.deinit();
        allocator.destroy(body);
    }

    try std.testing.expectEqualSlices(u8, "PassKeeZ", body.meta.gen);
    try std.testing.expectEqualSlices(u8, "My Passkeys", body.meta.name);

    const e1 = body.getEntryById("0e695c28-42f9-43e4-9aca-3f71cd701dc0".*).?;
    try std.testing.expectEqualStrings("Bundeswehr", e1.name.?);
    try std.testing.expectEqualStrings("They will call me back next week.", e1.notes.?);
    try std.testing.expectEqualStrings("supersecret", e1.secret.?);
    try std.testing.expectEqualStrings("github.com", e1.url.?);
    try std.testing.expectEqualSlices(u8, "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1", e1.user.?.id.?);
    try std.testing.expectEqualSlices(u8, "r4gus", e1.user.?.name.?);
    try std.testing.expectEqualSlices(u8, "David Sugar", e1.user.?.display_name.?);
    try std.testing.expectEqualSlices(u8, "work", e1.tags.?[0]);
    try std.testing.expectEqualSlices(u8, "VIP", e1.tags.?[1]);

    const e2 = body.getEntryById("28d84315-4f68-481f-bc26-6c44c52e0038".*).?;
    try std.testing.expectEqualStrings("Github", e2.name.?);
    try std.testing.expectEqualStrings("12345678", e2.secret.?);
    try std.testing.expectEqualStrings("github.com", e2.url.?);
    try std.testing.expectEqualSlices(u8, "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2", e2.user.?.id.?);
    try std.testing.expectEqualSlices(u8, "r4gus", e2.user.?.name.?);
    try std.testing.expectEqualSlices(u8, "David Sugar", e2.user.?.display_name.?);
    try std.testing.expectEqualSlices(u8, "dev", e2.tags.?[0]);
}

test "serialize body #2" {
    const mockup = struct {
        pub fn ms() i64 {
            return 1720033910;
        }
    };
    const allocator = std.testing.allocator;
    const raw = "\xa3\x00\xa3\x00\x68\x50\x61\x73\x73\x4b\x65\x65\x5a\x01\x6b\x4d\x79\x20\x50\x61\x73\x73\x6b\x65\x79\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x01\x83\xa9\x00\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x01\x6a\x42\x75\x6e\x64\x65\x73\x77\x65\x68\x72\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x78\x21\x54\x68\x65\x79\x20\x77\x69\x6c\x6c\x20\x63\x61\x6c\x6c\x20\x6d\x65\x20\x62\x61\x63\x6b\x20\x6e\x65\x78\x74\x20\x77\x65\x65\x6b\x2e\x04\x4b\x73\x75\x70\x65\x72\x73\x65\x63\x72\x65\x74\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x08\x78\x24\x30\x31\x39\x30\x38\x38\x36\x65\x2d\x63\x31\x30\x62\x2d\x37\x61\x39\x32\x2d\x39\x64\x30\x62\x2d\x64\x39\x39\x33\x38\x36\x64\x33\x30\x37\x35\x65\x09\x82\x64\x77\x6f\x72\x6b\x63\x56\x49\x50\xa8\x00\x78\x24\x32\x38\x64\x38\x34\x33\x31\x35\x2d\x34\x66\x36\x38\x2d\x34\x38\x31\x66\x2d\x62\x63\x32\x36\x2d\x36\x63\x34\x34\x63\x35\x32\x65\x30\x30\x33\x38\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x04\x48\x31\x32\x33\x34\x35\x36\x37\x38\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x08\x78\x24\x30\x31\x39\x30\x38\x38\x36\x65\x2d\x63\x31\x30\x62\x2d\x37\x61\x39\x32\x2d\x39\x64\x30\x62\x2d\x64\x39\x39\x33\x38\x36\x64\x33\x30\x37\x35\x65\x09\x81\x63\x64\x65\x76\xa7\x00\x78\x24\x30\x31\x39\x30\x38\x38\x37\x34\x2d\x35\x31\x64\x65\x2d\x37\x65\x66\x31\x2d\x61\x39\x66\x64\x2d\x61\x61\x61\x65\x37\x37\x32\x33\x31\x38\x39\x37\x01\x66\x47\x69\x74\x68\x75\x62\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x05\xa6\x01\x02\x03\x26\x20\x01\x21\x58\x20\x00\xec\x46\xbb\x48\x5e\xa6\x0f\x89\x68\xc9\x81\x5a\xca\x32\x90\x45\x50\xde\xe4\x17\xb2\x04\x99\xbc\xca\x11\x47\x64\x29\xd8\xe9\x22\x58\x20\x00\x62\xf7\x19\x97\x14\x97\xad\x20\x57\xa0\x86\x2f\xcd\x46\x8e\xf5\xd7\x74\x0c\x37\xef\x02\x0b\x5a\xda\x48\x30\x36\x34\x0f\x3d\x23\x58\x20\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d\x06\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x07\xa3\x00\x50\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2\x01\x65\x72\x34\x67\x75\x73\x02\x6b\x44\x61\x76\x69\x64\x20\x53\x75\x67\x61\x72\x08\x78\x24\x30\x31\x39\x30\x38\x38\x39\x62\x2d\x30\x36\x33\x36\x2d\x37\x61\x38\x32\x2d\x39\x32\x64\x32\x2d\x61\x35\x61\x64\x38\x33\x38\x66\x65\x63\x31\x64\x02\x83\xa4\x00\x78\x24\x30\x31\x39\x30\x38\x38\x36\x65\x2d\x63\x31\x30\x62\x2d\x37\x61\x39\x32\x2d\x39\x64\x30\x62\x2d\x64\x39\x39\x33\x38\x36\x64\x33\x30\x37\x35\x65\x01\x69\x70\x61\x73\x73\x77\x6f\x72\x64\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x04\x82\x78\x24\x30\x65\x36\x39\x35\x63\x32\x38\x2d\x34\x32\x66\x39\x2d\x34\x33\x65\x34\x2d\x39\x61\x63\x61\x2d\x33\x66\x37\x31\x63\x64\x37\x30\x31\x64\x63\x30\x78\x24\x32\x38\x64\x38\x34\x33\x31\x35\x2d\x34\x66\x36\x38\x2d\x34\x38\x31\x66\x2d\x62\x63\x32\x36\x2d\x36\x63\x34\x34\x63\x35\x32\x65\x30\x30\x33\x38\xa4\x00\x78\x24\x30\x31\x39\x30\x38\x38\x36\x66\x2d\x65\x63\x39\x31\x2d\x37\x66\x32\x37\x2d\x38\x37\x64\x33\x2d\x63\x63\x61\x37\x63\x35\x64\x38\x37\x33\x32\x38\x01\x68\x70\x61\x73\x73\x6b\x65\x79\x73\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x03\x81\x78\x24\x30\x31\x39\x30\x38\x38\x39\x62\x2d\x30\x36\x33\x36\x2d\x37\x61\x38\x32\x2d\x39\x32\x64\x32\x2d\x61\x35\x61\x64\x38\x33\x38\x66\x65\x63\x31\x64\xa5\x00\x78\x24\x30\x31\x39\x30\x38\x38\x39\x62\x2d\x30\x36\x33\x36\x2d\x37\x61\x38\x32\x2d\x39\x32\x64\x32\x2d\x61\x35\x61\x64\x38\x33\x38\x66\x65\x63\x31\x64\x01\x6a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x02\xa2\x00\x1a\x66\x85\xa2\x76\x01\x1a\x66\x85\xa2\x76\x04\x81\x78\x24\x30\x31\x39\x30\x38\x38\x37\x34\x2d\x35\x31\x64\x65\x2d\x37\x65\x66\x31\x2d\x61\x39\x66\x64\x2d\x61\x61\x61\x65\x37\x37\x32\x33\x31\x38\x39\x37\x05\x78\x24\x30\x31\x39\x30\x38\x38\x36\x66\x2d\x65\x63\x39\x31\x2d\x37\x66\x32\x37\x2d\x38\x37\x64\x33\x2d\x63\x63\x61\x37\x63\x35\x64\x38\x37\x33\x32\x38";

    var body = try Body.new("PassKeeZ", "My Passkeys", allocator, mockup.ms, std.crypto.random);
    defer {
        body.deinit();
        allocator.destroy(body);
    }

    // +- passwords
    // |  > Bundeswehr
    // |  > Github
    // |
    // +- passkeys
    //    |
    //    +- github.com
    //       > ...
    const g1 = try body.newGroup("passwords");
    @memcpy(g1.uuid[0..], "0190886e-c10b-7a92-9d0b-d99386d3075e");

    const g2 = try body.newGroup("passkeys");
    @memcpy(g2.uuid[0..], "0190886f-ec91-7f27-87d3-cca7c5d87328");

    const g3 = try body.newGroup("github.com");
    @memcpy(g3.uuid[0..], "0190889b-0636-7a82-92d2-a5ad838fec1d");

    try g2.addGroup(g3);

    var e1 = try body.newEntry();
    @memcpy(e1.uuid[0..], "0e695c28-42f9-43e4-9aca-3f71cd701dc0"); // so we have reproducible results
    try e1.setName("Bundeswehr");
    try e1.setNotes("They will call me back next week.");
    try e1.setSecret("supersecret");
    try e1.setUrl("github.com");
    try e1.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf1",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    try e1.addTag("work");
    try e1.addTag("VIP");

    var e2 = try body.newEntry();
    @memcpy(e2.uuid[0..], "28d84315-4f68-481f-bc26-6c44c52e0038"); // so we have reproducible results
    try e2.setName("Github");
    try e2.setSecret("12345678");
    try e2.setUrl("github.com");
    try e2.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    try e2.addTag("dev");

    try g1.addEntry(e1);
    try g1.addEntry(e2);

    var e3 = try body.newEntry();
    @memcpy(e3.uuid[0..], "01908874-51de-7ef1-a9fd-aaae77231897");
    try e3.setName("Github");
    try e3.setUrl("github.com");
    try e3.setUser(.{
        .id = "\xb3\x9d\xe5\x0b\xc1\x08\x0e\xb7\x96\xf0\x9f\xee\x8e\x30\xc7\xf2",
        .name = "r4gus",
        .display_name = "David Sugar",
    });
    e3.setKey(cbor.cose.Key{
        .P256 = .{
            .alg = cbor.cose.Algorithm.Es256,
            .crv = cbor.cose.Curve.P256,
            .kty = cbor.cose.KeyType.Ec2,
            .x = "\x00\xec\x46\xbb\x48\x5e\xa6\x0f\x89\x68\xc9\x81\x5a\xca\x32\x90\x45\x50\xde\xe4\x17\xb2\x04\x99\xbc\xca\x11\x47\x64\x29\xd8\xe9".*,
            .y = "\x00\x62\xf7\x19\x97\x14\x97\xad\x20\x57\xa0\x86\x2f\xcd\x46\x8e\xf5\xd7\x74\x0c\x37\xef\x02\x0b\x5a\xda\x48\x30\x36\x34\x0f\x3d".*,
            .d = "\x29\x9b\xa4\x0f\x65\x47\xf9\xa5\x91\x63\x6b\xa3\xaa\xbc\xf5\x2a\xde\xde\xca\x32\x4d\x3d\x6e\x81\xc8\x30\x2d\x51\x99\xde\x9d\x0d".*,
        },
    });

    // Let's also test if the old entry reference is correctly removed from group 1
    // after the reassignment.
    try g1.addEntry(e3);
    try g3.addEntry(e3);

    var arr = std.ArrayList(u8).init(allocator);
    defer arr.deinit();

    try body.serialize(arr.writer());

    try std.testing.expectEqualSlices(u8, raw, arr.items);
}
