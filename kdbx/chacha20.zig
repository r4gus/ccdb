const std = @import("std");
const assert = std.debug.assert;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Base64Decoder = std.base64.standard.Decoder;

pub const Nonce = "\xe8\x30\x09\x4b\x97\x20\x5d\x2a";

pub const ChaCha20 = struct {
    pub const nonce_length = 12;
    pub const key_length = 32;

    pub fn encrypt(c: []u8, m: []const u8, npub: [nonce_length]u8, k: [key_length]u8, index: u32) void {
        assert(c.len == m.len);
        assert(m.len <= 64 * (@as(u39, 1 << 32) - 1));

        ChaCha20IETF.xor(c[0..m.len], m, index, k, npub);
    }

    pub fn decrypt(m: []u8, c: []const u8, npub: [nonce_length]u8, k: [key_length]u8, index: u32) void {
        assert(c.len == m.len);

        ChaCha20IETF.xor(m[0..c.len], c, index, k, npub);
    }
};

test "decrypt protected data #1" {
    const stream_key = "\x43\x8a\xe9\x40\x78\xc8\xe6\xe5\xac\xdf\xcc\xc8\x9c\xcd\xde\x07\x85\x49\xd3\xe2\x63\x2b\x5f\xcd\x31\x37\x3c\x9b\x73\xd1\x34\xff\xc3\x0c\xc7\x18\x16\x68\x21\xae\x23\x04\xdf\xe1\x47\x67\x85\x30\x23\xb7\xbd\x44\x75\x34\x56\x7f\x4b\xb6\xab\x00\xeb\x42\x6f\x9e";
    const password_enc = "\x92\x4d\x6b\xe5";
    var password: [4]u8 = .{0} ** 4;
    var digest: [64]u8 = undefined;

    Sha512.hash(stream_key, &digest, .{});
    ChaCha20.decrypt(&password, password_enc, digest[32..44].*, digest[0..32].*, 0);

    try std.testing.expectEqualStrings("1234", &password);
}

test "decrypt protected data #2" {
    const stream_key = "\x4b\xb4\x0b\xf1\x38\x54\x75\x45\x6f\x89\x99\xbf\x83\xfb\x45\xb7\xf4\xae\xd6\x15\xa3\x79\x85\x9c\x25\x89\xd6\x01\x8f\xdd\x6e\x5c\x80\xad\x19\xe2\xd0\x4e\x05\xcd\xc7\x8e\x83\xaf\xa4\xf5\x5d\x71\xb1\x5b\x63\xe4\xa2\x35\x34\x1c\xdf\x41\x81\x19\x6f\x9c\xe0\xd3";
    const test_vector: [3][2][]const u8 = .{
        .{ "YeM3ssVT06nJ1g==", "helloworld" },
        .{ "m2NgXg==", "1234" },
        .{ "q1akNQ==", "9876" },
    };

    var digest: [64]u8 = undefined;
    Sha512.hash(stream_key, &digest, .{});

    var buffer: [1024]u8 = undefined;
    var i: usize = 0;

    for (test_vector) |e| {
        const size = try Base64Decoder.calcSizeForSlice(e[0]);
        const m = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(m);
        try Base64Decoder.decode(m, e[0]);

        @memcpy(buffer[i .. i + size], m);
        i += size;
    }

    const pw = try std.testing.allocator.alloc(u8, i);
    defer std.testing.allocator.free(pw);

    ChaCha20.decrypt(pw, buffer[0..i], digest[32..44].*, digest[0..32].*, 0);
    try std.testing.expectEqualStrings("helloworld12349876", pw);
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

pub const ChaCha20Context = struct {
    keystream32: [16]u32,
    position: usize,
    key: [32]u8,
    nonce: [12]u8,
    counter: u64,

    state: [16]u32,

    pub fn init(key: [32]u8, nonce: [12]u8, counter: u64) @This() {
        var ctx: @This() = undefined;
        chacha20_init_block(&ctx, key, nonce);
        chacha20_block_set_counter(&ctx, counter);
        ctx.counter = counter;
        ctx.position = 64;
        return ctx;
    }

    pub fn xor(ctx: *@This(), bytes: []u8) void {
        const keystream8 = @as([*c]u8, @ptrCast(ctx.keystream32[0..].ptr));
        for (bytes) |*b| {
            if (ctx.position >= 64) {
                chacha20_block_next(ctx);
                ctx.position = 0;
            }
            b.* ^= keystream8[@as(usize, @intCast(ctx.position))];
            ctx.position += 1;
        }
    }
};

fn rotl32(x: u32, n: u5) u32 {
    return (x << n) | (x >> (31 - n + 1)); // the +1 is a workaround to satisfy the compiler (instead of 32)
}

fn pack4(a: []const u8) u32 {
    var res: u32 = 0;
    res |= @as(u32, @intCast(a[0])) << 0 * 8;
    res |= @as(u32, @intCast(a[1])) << 1 * 8;
    res |= @as(u32, @intCast(a[2])) << 2 * 8;
    res |= @as(u32, @intCast(a[3])) << 3 * 8;
    return res;
}

fn unpack4(src: u32, dst: []const u8) void {
    dst[0] = @as(u8, @intCast((src >> 0 * 8) & 0xff));
    dst[1] = @as(u8, @intCast((src >> 1 * 8) & 0xff));
    dst[2] = @as(u8, @intCast((src >> 2 * 8) & 0xff));
    dst[3] = @as(u8, @intCast((src >> 3 * 8) & 0xff));
}

fn chacha20_init_block(ctx: *ChaCha20Context, key: [32]u8, nonce: [12]u8) void {
    ctx.key = key;
    ctx.nonce = nonce;

    const magic_constant: []const u8 = "expand 32-byte k";

    ctx.state[0] = pack4(magic_constant[0..4]);
    ctx.state[1] = pack4(magic_constant[4..8]);
    ctx.state[2] = pack4(magic_constant[8..12]);
    ctx.state[3] = pack4(magic_constant[12..16]);
    ctx.state[4] = pack4(key[0..4]);
    ctx.state[5] = pack4(key[4..8]);
    ctx.state[6] = pack4(key[8..12]);
    ctx.state[7] = pack4(key[12..16]);
    ctx.state[8] = pack4(key[16..20]);
    ctx.state[9] = pack4(key[20..24]);
    ctx.state[10] = pack4(key[24..28]);
    ctx.state[11] = pack4(key[28..32]);
    // 64 bit counter initialized to zero by default.
    ctx.state[12] = 0;
    ctx.state[13] = pack4(nonce[0..4]);
    ctx.state[14] = pack4(nonce[4..8]);
    ctx.state[15] = pack4(nonce[8..12]);

    ctx.nonce = nonce;
}

fn chacha20_block_set_counter(ctx: *ChaCha20Context, counter: u64) void {
    ctx.state[12] = @as(u32, @intCast(counter));
    ctx.state[13] = pack4(ctx.nonce[0..4]) + @as(u32, @intCast(counter >> 32));
}

inline fn quarterround(x: []u32, a: usize, b: usize, c: usize, d: usize) void {
    x[a] +%= x[b];
    x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] +%= x[d];
    x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] +%= x[b];
    x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] +%= x[d];
    x[b] = rotl32(x[b] ^ x[c], 7);
}

fn chacha20_block_next(ctx: *ChaCha20Context) void {
    for (ctx.keystream32[0..], ctx.state[0..]) |*k, s| k.* = s;

    for (0..10) |_| {
        quarterround(ctx.keystream32[0..], 0, 4, 8, 12);
        quarterround(ctx.keystream32[0..], 1, 5, 9, 13);
        quarterround(ctx.keystream32[0..], 2, 6, 10, 14);
        quarterround(ctx.keystream32[0..], 3, 7, 11, 15);
        quarterround(ctx.keystream32[0..], 0, 5, 10, 15);
        quarterround(ctx.keystream32[0..], 1, 6, 11, 12);
        quarterround(ctx.keystream32[0..], 2, 7, 8, 13);
        quarterround(ctx.keystream32[0..], 3, 4, 9, 14);
    }

    for (ctx.keystream32[0..], ctx.state[0..]) |*k, s| k.* +%= s;
    ctx.state[12] +%= 1;
    if (0 == ctx.state[12]) {
        // wrap around occured, increment higher 32 bits of counter
        ctx.state[13] +%= 1;
        // Limited to 2^64 blocks of 64 bytes each.
        std.debug.assert(0 != ctx.state[13]);
    }
}

test "decrypt protected with custom impl" {
    const stream_key = "\x4b\xb4\x0b\xf1\x38\x54\x75\x45\x6f\x89\x99\xbf\x83\xfb\x45\xb7\xf4\xae\xd6\x15\xa3\x79\x85\x9c\x25\x89\xd6\x01\x8f\xdd\x6e\x5c\x80\xad\x19\xe2\xd0\x4e\x05\xcd\xc7\x8e\x83\xaf\xa4\xf5\x5d\x71\xb1\x5b\x63\xe4\xa2\x35\x34\x1c\xdf\x41\x81\x19\x6f\x9c\xe0\xd3";
    const test_vector: [3][2][]const u8 = .{
        .{ "YeM3ssVT06nJ1g==", "helloworld" },
        .{ "m2NgXg==", "1234" },
        .{ "q1akNQ==", "9876" },
    };

    var digest: [64]u8 = undefined;
    Sha512.hash(stream_key, &digest, .{});

    var ctx = ChaCha20Context.init(digest[0..32].*, digest[32..44].*, 0);

    for (test_vector) |e| {
        const size = try Base64Decoder.calcSizeForSlice(e[0]);
        const m = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(m);
        try Base64Decoder.decode(m, e[0]);

        ctx.xor(m);
        try std.testing.expectEqualStrings(e[1], m);
    }
}
