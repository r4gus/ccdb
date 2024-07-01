const std = @import("std");
const tests = @import("tests.zig");
const cbor = @import("zbor");

const argon2 = std.crypto.pwhash.argon2;
const chacha = @import("chacha.zig");
const XChaCha20IETF = chacha.XChaCha20IETF;

// +------------------------------------------------+
// | Blocks                                         |
// +------------------------------------------------+

// +------------------------------------------------+
// | Options                                        |
// +------------------------------------------------+

pub const OptionType = enum(u16) {
    /// delimits the end of the optional fields
    endofopt = 0,
    /// UTF-8 string containing human-readable comment text
    comment = 1,
    /// UTF-8 string in the Custom Data portion
    custom_utf8 = 2988,
    /// binary octets in the Custom Data portion
    custom_bin = 2989,

    pub fn fromRaw(i: [2]u8) !@This() {
        const i_ = @as(u16, @intCast(i[1])) << 8 | @as(u16, @intCast(i[0]));
        return switch (i_) {
            0 => .endofopt,
            1 => .comment,
            2988 => .custom_utf8,
            2989 => .custom_bin,
            else => error.InvalidArgument,
        };
    }
};

pub const Option = struct {
    type: OptionType,
    pen: ?u32,
    value: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const @This()) void {
        self.allocator.free(self.value);
    }
};

//pub const OptionIterator = struct {
//    data: []const u8,
//    i: usize = 0,
//
//    pub fn next(self: *@This()) ?Option {
//        if (self.i >= self.data.len) return null;
//        if (self.data[self.i..].len < 4) {
//            self.i = self.data.len;
//            return null;
//        }
//        const t = OptionType.fromRaw(self.data[0..2].*) catch {
//            self.i = self.data.len;
//            return null;
//        };
//
//        const pen: ?u32 = switch (t) {
//            .custom_utf8, .custom_bin => blk: {
//                if (self.data[self.i..].len < 8) {
//                    self.i = self.data.len;
//                    return null;
//                }
//
//                const x = self.data[4..8];
//                break :blk @as(u16, @intCast(x[3])) << 24 | @as(u16, @intCast(x[2])) << 16 | @as(u16, @intCast(x[1])) << 8 | @as(u16, @intCast(x[0]));
//            },
//            else => null,
//        };
//
//        const length = @as(usize, @intCast(self.data[2..4]));
//        const offset = if (pen == null) 4 else 8;
//        var next = offset + length;
//        const x_ = length % 4;
//        if (x_ != 0) {
//
//        }
//    }
//};
