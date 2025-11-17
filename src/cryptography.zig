// std
const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

// managed dependencies
const EllipticCurveLib = @import("elliptic-curve.zig");
const FieldElement = EllipticCurveLib.FieldElement(u256);
const CurvePoint = EllipticCurveLib.CurvePoint(u256);

const secp256k1_a = 0;
const secp256k1_b = 7;
const secp256k1_a_fe = FieldElement.init(secp256k1_a, secp256k1_p);
const secp256k1_b_fe = FieldElement.init(secp256k1_b, secp256k1_p);

pub const G = CurvePoint.init(
    FieldElement.init(0x79be667e_f9dcbbac_55a06295_ce870b07_029bfcdb_2dce28d9_59f2815b_16f81798, secp256k1_p),
    FieldElement.init(0x483ada77_26a3c465_5da4fbfc_0e1108a8_fd17b448_a6855419_9c47d08f_fb10d4b8, secp256k1_p),
    secp256k1_a_fe,
    secp256k1_b_fe,
);

pub const secp256k1_p = 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_fffffc2f;
pub const secp256k1_n = 0xffffffff_ffffffff_ffffffff_fffffffe_baaedce6_af48a03b_bfd25e8c_d0364141;

pub const Signature = struct {
    r: u256,
    s: u256,

    /// Returns a slice of the `out` buffer
    pub fn serialize(self: *const Signature, out: *[72]u8) []u8 {
        // @TODO does not perfectly conform to Bitcoin Core
        // do simplest possible serialization, then remove excessive padding
        std.mem.copyForwards(u8, out[0..5], &.{ 0x30, 0x46, 0x02, 0x21, 0x00 });
        std.mem.writeInt(u256, out[5..37], self.r, .big);
        std.mem.copyForwards(u8, out[37..40], &.{ 0x02, 0x21, 0x00 });
        std.mem.writeInt(u256, out[40..72], self.s, .big);
        var sig_len: usize = 72;

        while (out[4] == 0x00 and (out[5] & 0b1000_0000) == 0) {
            // remove 0x00 and move all next bytes once to the left
            for (4..sig_len - 1) |index| out[index] = out[index + 1];
            sig_len = sig_len - 1;
            out[3] = out[3] - 1; // decrement length of r
        }

        const s_len_index = out[3] + 5;
        while (out[out[3] + 6] == 0x00 and (out[out[3] + 7] & 0b1000_0000) == 0) {
            // remove 0x00 and move all next bytes once to the left
            for ((out[3] + 6)..sig_len - 1) |index| out[index] = out[index + 1];
            sig_len = sig_len - 1;
            out[s_len_index] = out[s_len_index] - 1; // decrement length of s
        }

        out[1] = @intCast(sig_len - 2);
        return out[0..sig_len];
    }

    pub fn parse(bytes: []const u8) Signature {
        assert(bytes[0] == 0x30);
        assert(bytes.len == 2 + bytes[1]);
        assert(bytes[2] == 0x02);
        const r_len = bytes[3];
        assert(4 + r_len < bytes.len);
        assert(bytes[4 + r_len] == 0x02);
        const s_len_index = 4 + r_len + 1;
        assert(s_len_index < bytes.len);
        const s_len = bytes[4 + r_len + 1];
        assert(s_len_index + s_len == bytes.len - 1);
        assert(r_len == 32 or r_len == 33);
        assert(s_len == 32 or s_len == 33);
        assert(r_len + s_len + 6 == bytes.len);

        var r_buffer: [32]u8 = .{0} ** 32;
        {
            const r_first_index: usize = if (r_len == 33) 5 else 4;
            for (&r_buffer, bytes[r_first_index..][0..32]) |*d, s| d.* = s;
        }
        var s_buffer: [32]u8 = .{0} ** 32;
        {
            const s_first_index: usize = if (s_len == 33) s_len_index + 2 else s_len_index + 1;
            for (&s_buffer, bytes[s_first_index..][0..32]) |*d, s| d.* = s;
        }

        return .{
            .r = std.mem.readInt(u256, &r_buffer, .big),
            .s = std.mem.readInt(u256, &s_buffer, .big),
        };
    }
};

pub fn hashAsU256(message: []const u8) u256 {
    var z_bytes: [32]u8 = undefined;
    Sha256.hash(message, &z_bytes, .{});
    return std.mem.readInt(u256, &z_bytes, .big);
}

pub fn generateKeyPair() struct { pubk: CurvePoint, prvk: u256 } {
    const e = std.crypto.random.int(u256);
    const P = G.muli(e);
    return .{ .pubk = P, .prvk = e };
}

pub fn sign(message_hash: u256, private_key: u256) Signature {
    const k = std.crypto.random.int(u256);
    const r = G.muli(k).x.?.value;
    const k_inv = FieldElement.modpow(k, secp256k1_n - 2, secp256k1_n);
    const s: u256 = s_calc: { // s = (r * e + z) * k_inv (mod n)
        var temp: u512 = r;
        temp = temp * private_key;
        temp = @mod(temp, secp256k1_n);
        temp = temp + message_hash;
        temp = @mod(temp, secp256k1_n);
        temp = temp * k_inv;
        temp = @mod(temp, secp256k1_n);
        if (temp > secp256k1_n / 2)
            temp = secp256k1_n - temp;
        break :s_calc @intCast(temp);
    };
    return Signature{ .r = r, .s = s };
}

pub fn verify(message_hash: u256, public_key: CurvePoint, sig: Signature) bool {
    const s_inv = FieldElement.modpow(sig.s, secp256k1_n - 2, secp256k1_n);

    const u: u256 = u_calc: { // u = z * s_inv (mod n)
        var temp: u512 = message_hash;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :u_calc @intCast(temp);
    };

    const v: u256 = v_calc: { // v = r * s_inv (mod n)
        var temp: u512 = sig.r;
        temp = temp * s_inv;
        temp = @mod(temp, secp256k1_n);
        break :v_calc @intCast(temp);
    };

    return G.muli(u).add(public_key.muli(v)).x.?.value == sig.r;
}

//#region TESTS #########################################################################

const expect = std.testing.expect;

test "order of G is indeed n" {
    try expect(G.muli(secp256k1_n).atInfinity());
}

test "hash" {
    const hash_result = hashAsU256("The quick brown fox jumps over the lazy dog");
    try expect(hash_result == 0xd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592);
}

test "signing message" {
    const keys = generateKeyPair();
    const z = hashAsU256("my message");
    const signature: Signature = sign(z, keys.prvk);
    const valid = verify(z, keys.pubk, signature);
    try expect(valid);
}

test "serialized signature" {
    const sig: Signature = .{
        .r = hashAsU256("idk"),
        .s = hashAsU256("anything"),
    };
    var serialized_sig_buffer: [72]u8 = undefined;
    const serialized_sig = sig.serialize(&serialized_sig_buffer);
    const sig_parsed = Signature.parse(serialized_sig);
    try std.testing.expectEqualDeep(sig, sig_parsed);

    const sig2 = Signature.parse(&.{ 0x30, 0x44, 0x02, 0x20, 0x39, 0x43, 0x58, 0x0d, 0x54, 0x54, 0x70, 0xe1, 0x9b, 0xd9, 0xc7, 0x92, 0x4e, 0x08, 0x11, 0xc3, 0x34, 0x83, 0x16, 0xa7, 0xef, 0x12, 0x9b, 0xcb, 0x6b, 0xe1, 0xab, 0x03, 0x88, 0x76, 0x95, 0x98, 0x02, 0x20, 0x41, 0xe6, 0x3a, 0xb6, 0x08, 0x7b, 0x79, 0x20, 0x70, 0x59, 0x26, 0xf6, 0xb9, 0x50, 0x04, 0xd0, 0x8e, 0x01, 0xc1, 0xf8, 0x16, 0x38, 0xca, 0x71, 0x53, 0x97, 0xa7, 0xf0, 0x81, 0x6e, 0xc8, 0x87 });
    try std.testing.expectEqualDeep(
        Signature{
            .r = 25900818835625129619026014211686450729698931365216873087254722392658963502488,
            .s = 29807115191703043155797809226099545662063525568305845350204007208552481343623,
        },
        sig2,
    );
}

//#endregion
