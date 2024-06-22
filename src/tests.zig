const std = @import("std");
const root = @import("root.zig");

test "serialize Version" {
    const v = root.Version{};

    var raw = std.ArrayList(u8).init(std.testing.allocator);
    defer raw.deinit();

    try v.serialize(raw.writer());

    try std.testing.expectEqualSlices(u8, "\x43\x43\x44\x42\x01\x00\x00\x00", raw.items);
}
