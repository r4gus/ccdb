const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const maxInt = math.maxInt;

/// XChaCha20 (nonce-extended version of the IETF ChaCha20 variant) stream cipher
pub const XChaCha20IETF = XChaChaIETF(20);

// Non-vectorized implementation of the core function
fn ChaChaNonVecImpl(comptime rounds_nb: usize) type {
    return struct {
        const BlockVec = [16]u32;

        fn initContext(key: [8]u32, d: [4]u32) BlockVec {
            const c = "expand 32-byte k";
            const constant_le = comptime [4]u32{
                mem.readInt(u32, c[0..4], .little),
                mem.readInt(u32, c[4..8], .little),
                mem.readInt(u32, c[8..12], .little),
                mem.readInt(u32, c[12..16], .little),
            };
            return BlockVec{
                constant_le[0], constant_le[1], constant_le[2], constant_le[3],
                key[0],         key[1],         key[2],         key[3],
                key[4],         key[5],         key[6],         key[7],
                d[0],           d[1],           d[2],           d[3],
            };
        }

        const QuarterRound = struct {
            a: usize,
            b: usize,
            c: usize,
            d: usize,
        };

        fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
            return QuarterRound{
                .a = a,
                .b = b,
                .c = c,
                .d = d,
            };
        }

        inline fn chacha20Core(x: *BlockVec, input: BlockVec) void {
            x.* = input;

            const rounds = comptime [_]QuarterRound{
                Rp(0, 4, 8, 12),
                Rp(1, 5, 9, 13),
                Rp(2, 6, 10, 14),
                Rp(3, 7, 11, 15),
                Rp(0, 5, 10, 15),
                Rp(1, 6, 11, 12),
                Rp(2, 7, 8, 13),
                Rp(3, 4, 9, 14),
            };

            comptime var j: usize = 0;
            inline while (j < rounds_nb) : (j += 2) {
                inline for (rounds) |r| {
                    x[r.a] +%= x[r.b];
                    x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 16));
                    x[r.c] +%= x[r.d];
                    x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 12));
                    x[r.a] +%= x[r.b];
                    x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 8));
                    x[r.c] +%= x[r.d];
                    x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 7));
                }
            }
        }

        inline fn hashToBytes(out: *[64]u8, x: BlockVec) void {
            for (0..4) |i| {
                mem.writeInt(u32, out[16 * i + 0 ..][0..4], x[i * 4 + 0], .little);
                mem.writeInt(u32, out[16 * i + 4 ..][0..4], x[i * 4 + 1], .little);
                mem.writeInt(u32, out[16 * i + 8 ..][0..4], x[i * 4 + 2], .little);
                mem.writeInt(u32, out[16 * i + 12 ..][0..4], x[i * 4 + 3], .little);
            }
        }

        inline fn contextFeedback(x: *BlockVec, ctx: BlockVec) void {
            for (0..16) |i| {
                x[i] +%= ctx[i];
            }
        }

        fn chacha20Xor(out: []u8, in: []const u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var buf: [64]u8 = undefined;
            var i: usize = 0;
            while (i + 64 <= in.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                for (0..64) |j| {
                    xout[j] = xin[j];
                }
                for (0..64) |j| {
                    xout[j] ^= buf[j];
                }
                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < in.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                for (0..in.len % 64) |j| {
                    xout[j] = xin[j] ^ buf[j];
                }
            }
        }

        fn chacha20SeekXor(io: []u8, key: [8]u32, nonce_and_counter: [4]u32, offset: usize, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var buf: [64]u8 = undefined;
            var i: usize = 0;
            var m: usize = 0;
            while (i + 64 <= offset + io.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                // TODO: this can be used as a side channel to obtain information
                // about what part of the key stream was obtained.
                for (0..64) |k| {
                    if (i + k >= offset) {
                        io[m] ^= buf[k];
                        m += 1;
                    }
                }

                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < offset + io.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                // TODO: this can be used as a side channel to obtain information
                // about what part of the key stream was obtained.
                for (0..64) |k| {
                    if (m >= io.len) break;

                    if (i + k >= offset) {
                        io[m] ^= buf[k];
                        m += 1;
                    }
                }
            }
        }

        fn chacha20Stream(out: []u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var i: usize = 0;
            while (i + 64 <= out.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(out[i..][0..64], x);
                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < out.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);

                var buf: [64]u8 = undefined;
                hashToBytes(buf[0..], x);
                @memcpy(out[i..], buf[0 .. out.len - i]);
            }
        }

        fn chacha20SeekStream(out: []u8, key: [8]u32, nonce_and_counter: [4]u32, offset: usize, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var i: usize = 0;
            var j: usize = 0;
            while (i + 64 <= offset + out.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);

                var buf: [64]u8 = undefined;
                hashToBytes(buf[0..], x);

                // TODO: this can be used as a side channel to obtain information
                // about what part of the key stream was obtained.
                for (0..64) |k| {
                    if (i + k >= offset) {
                        out[j] = buf[k];
                        j += 1;
                    } else {
                        out[0] = buf[k];
                    }
                }

                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < offset + out.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);

                var buf: [64]u8 = undefined;
                hashToBytes(buf[0..], x);

                // TODO: this can be used as a side channel to obtain information
                // about what part of the key stream was obtained.
                for (0..64) |k| {
                    if (j >= out.len) break;

                    if (i + k >= offset) {
                        out[j] = buf[k];
                        j += 1;
                    } else {
                        out[0] = buf[k];
                    }
                }
            }
        }

        fn hchacha20(input: [16]u8, key: [32]u8) [32]u8 {
            var c: [4]u32 = undefined;
            for (c, 0..) |_, i| {
                c[i] = mem.readInt(u32, input[4 * i ..][0..4], .little);
            }
            const ctx = initContext(keyToWords(key), c);
            var x: BlockVec = undefined;
            chacha20Core(x[0..], ctx);
            var out: [32]u8 = undefined;
            mem.writeInt(u32, out[0..4], x[0], .little);
            mem.writeInt(u32, out[4..8], x[1], .little);
            mem.writeInt(u32, out[8..12], x[2], .little);
            mem.writeInt(u32, out[12..16], x[3], .little);
            mem.writeInt(u32, out[16..20], x[12], .little);
            mem.writeInt(u32, out[20..24], x[13], .little);
            mem.writeInt(u32, out[24..28], x[14], .little);
            mem.writeInt(u32, out[28..32], x[15], .little);
            return out;
        }
    };
}

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    for (0..8) |i| {
        k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    }
    return k;
}

fn extend(key: [32]u8, nonce: [24]u8, comptime rounds_nb: usize) struct { key: [32]u8, nonce: [12]u8 } {
    var subnonce: [12]u8 = undefined;
    @memset(subnonce[0..4], 0);
    subnonce[4..].* = nonce[16..24].*;
    return .{
        .key = ChaChaNonVecImpl(rounds_nb).hchacha20(nonce[0..16].*, key),
        .nonce = subnonce,
    };
}

fn ChaChaIETF(comptime rounds_nb: usize) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 12;
        /// Key length in bytes.
        pub const key_length = 32;
        /// Block length in bytes.
        pub const block_length = 64;

        /// Add the output of the ChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(in.len == out.len);
            assert(in.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaNonVecImpl(rounds_nb).chacha20Xor(out, in, keyToWords(key), d, false);
        }

        /// Add the output of the ChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn seekXor(io: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8, offset: usize) void {
            assert(io.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaNonVecImpl(rounds_nb).chacha20SeekXor(io, keyToWords(key), d, offset, false);
        }

        /// Write the output of the ChaCha20 stream cipher into `out`.
        pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(out.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaNonVecImpl(rounds_nb).chacha20Stream(out, keyToWords(key), d, false);
        }

        /// Write the output of the ChaCha20 stream cipher into `out`.
        pub fn seekStream(
            out: []u8,
            counter: u32,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
            offset: usize,
        ) void {
            assert(out.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaNonVecImpl(rounds_nb).chacha20SeekStream(
                out,
                keyToWords(key),
                d,
                offset,
                false,
            );
        }
    };
}

pub fn XChaChaIETF(comptime rounds_nb: usize) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 24;
        /// Key length in bytes.
        pub const key_length = 32;
        /// Block length in bytes.
        pub const block_length = 64;

        /// Add the output of the XChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).xor(out, in, counter, extended.key, extended.nonce);
        }

        /// Add the output of the XChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn seekXor(io: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8, offset: usize) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).seekXor(io, counter, extended.key, extended.nonce, offset);
        }

        /// Write the output of the XChaCha20 stream cipher into `out`.
        pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).stream(out, counter, extended.key, extended.nonce);
        }

        /// Write the output of the XChaCha20 stream cipher into `out`.
        pub fn seekStream(
            out: []u8,
            counter: u32,
            key: [key_length]u8,
            nonce: [nonce_length]u8,
            offset: usize,
        ) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).seekStream(out, counter, extended.key, extended.nonce, offset);
        }
    };
}
