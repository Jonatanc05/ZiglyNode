// std
const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

// not managed dependencies
const c_ripemd = @cImport({
    @cInclude("ripemd.c");
});

// managed dependencies
const EllipticCurveLib = @import("elliptic-curve.zig");
const CryptLib = @import("cryptography.zig");
const Util = @import("util.zig");

pub const Base58 = struct {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// Reads bytes as big endian.
    pub fn encode(bytes: []const u8, out: []u8) []u8 {
        if (bytes.len > 128) @panic("Base58.encode: bytes is too large, only up to 128 bytes supported");
        var bytes_extended: [128]u8 = undefined;
        if (bytes.len != 128)
            bytes_extended = [_]u8{0} ** 128;
        mem.copyForwards(u8, bytes_extended[(128 - bytes.len)..128], bytes);

        const bytes_as_u1024: u1024 = mem.readInt(u1024, &bytes_extended, .big);
        var remaining = bytes_as_u1024;
        var i = out.len;
        while (remaining > 0) {
            if (i == 0) std.debug.panic("Base58.encode: out is too small ({d} bytes) for the input {x}", .{ out.len, bytes_as_u1024 });
            i = i - 1;
            out[i] = alphabet[@intCast(remaining % 58)];
            remaining = remaining / 58;
        }
        return out[i..];
    }

    /// Writes out as big endian.
    pub fn decode(address_str: []const u8, out: *[1024 / 8]u8) []u8 {
        var bytes_as_u1024: u1024 = 0;
        {
            var multiplier: u1024 = 1;
            var i = address_str.len;
            while (i > 0) : (i -= 1) {
                bytes_as_u1024 += increment: {
                    const algarism = address_str[i - 1];
                    const algarism_value: u1024 = for (alphabet, 0..) |symbol, j| {
                        if (symbol == algarism) break @intCast(j);
                    } else @panic("Base58.decode: invalid character");
                    break :increment algarism_value * multiplier;
                };
                const result = @mulWithOverflow(multiplier, @as(u1024, 58));
                if (result[1] == 1) unreachable;
                multiplier = result[0];
            }
        }

        var i = out.len;
        while (i > 0) : (i -= 1) {
            out[i - 1] = @as(u8, @truncate(bytes_as_u1024));
            bytes_as_u1024 >>= 8;
            if (bytes_as_u1024 == 0) return out[i - 1 ..];
        }
        return out[0..];
    }
};

fn hash160(bytes: []const u8, out: [:0]u8) void {
    var sha256_1: [32:0]u8 = @splat(undefined);
    const unoptmize = @as(*[33]u8, @ptrCast(&sha256_1)).*;
    for (unoptmize) |i| asm volatile( "" : : [val] "r" (i));
    Sha256.hash(bytes, &sha256_1, .{});
    c_ripemd.calc_hash(&sha256_1, @ptrCast(out));
}

pub const Address = struct {
    pub fn fromPrivkey(privkey: u256, testnet: bool, buf: []u8) []u8 {
        const pubkey = CryptLib.G.muli(privkey);
        return fromPubkey(pubkey, testnet, buf);
    }

    pub fn fromPubkey(pubkey: EllipticCurveLib.CurvePoint(u256), testnet: bool, buf: []u8) []u8 {
        const hash160_data: [21]u8 = hash160_data: {
            var serialized_point: [33]u8 = undefined;
            pubkey.serialize(true, &serialized_point);
            var hash160_data: [21:0]u8 = @splat(undefined);
            hash160(&serialized_point, hash160_data[1..]);
            hash160_data[0] = if (testnet) 0x6f else 0x00;
            break :hash160_data hash160_data;
        };

        const checksum: [4]u8 = checksum: {
            var sha256_1: [32]u8 = undefined;
            Sha256.hash(&hash160_data, &sha256_1, .{});

            var sha256_2: [32]u8 = undefined;
            Sha256.hash(&sha256_1, &sha256_2, .{});

            var checksum: [4]u8 = undefined;
            mem.copyForwards(u8, &checksum, sha256_2[0..4]);
            break :checksum checksum;
        };

        const address = hash160_data ++ checksum;
        const encoded = Base58.encode(&address, buf[0..]);
        if (testnet) {
            return encoded;
        } else {
            buf[buf.len - encoded.len - 1] = '1';
            return buf[buf.len - encoded.len - 1 ..];
        }
    }

    /// If expect_testnet is not null, it will be checked against the address on Debug builds
    pub fn toPubkey(address: []const u8, expect_testnet: ?bool) []u8 {
        var buffer: [128]u8 = undefined;
        const decoded = Base58.decode(address, &buffer);
        std.debug.assert(decoded.len == 1 + 20 + 4); // net_flag + address + checksum
        if (expect_testnet != null) {
            if (expect_testnet.?) {
                std.debug.assert(decoded[0] == 0x6f);
            } else {
                std.debug.assert(decoded[0] == 0x00);
            }
        }
        std.debug.assert(mem.eql(
            u8,
            decoded[decoded.len - 4 ..][0..4],
            checksum: {
                var hash1: [32]u8 = undefined;
                Sha256.hash(decoded[0 .. decoded.len - 4], &hash1, .{});
                var hash2: [32]u8 = undefined;
                Sha256.hash(&hash1, &hash2, .{});
                break :checksum hash2[0..4];
            },
        ));
        return decoded[1 .. decoded.len - 4];
    }
};

pub const Tx = struct {
    version: u32 = 1,
    inputs: []TxInput,
    outputs: []TxOutput,
    witness: ?[][]u8 = null,
    locktime: u32 = 0,

    pub const TxInput = struct {
        txid: u256,
        index: u32,
        script_sig: []const u8,
        sequence: u32 = 0xfffffffd,
    };
    pub const TxOutput = struct {
        /// Given in sats
        amount: u64,
        script_pubkey: []const u8,
    };

    const InitP2PKHOpt = struct {
        testnet: bool,
        prev_txid: u256,
        prev_output_index: u32,
        /// Given in sats
        amount: u64,
        target_address: []const u8,
        alloc: mem.Allocator,
    };
    pub fn initP2PKH(opt: InitP2PKHOpt) !Tx {
        return .{
            .version = 1,
            .inputs = try opt.alloc.dupe(TxInput, &.{
                .{ .txid = opt.prev_txid, .index = opt.prev_output_index, .script_sig = &[_]u8{}, .sequence = 0xfffffffd },
            }),
            .outputs = try opt.alloc.dupe(TxOutput, &outputs: {
                var outputs: [1]TxOutput = .{
                    .{
                        .amount = opt.amount,
                        .script_pubkey = script_pubkey: {
                            var script_pubkey: []u8 = try opt.alloc.alloc(u8, 25);
                            const Op = Script.Opcode;
                            script_pubkey[0] = Op.OP_DUP;
                            script_pubkey[1] = Op.OP_HASH160;
                            script_pubkey[2] = 0x14; // P2PKH address is 20 bytes
                            mem.copyForwards(u8, script_pubkey[3..23], Address.toPubkey(opt.target_address, opt.testnet));
                            script_pubkey[23] = Op.OP_EQUALVERIFY;
                            script_pubkey[24] = Op.OP_CHECKSIG;
                            break :script_pubkey script_pubkey;
                        },
                    },
                };
                break :outputs outputs;
            }),
            .locktime = 0,
        };
    }

    pub fn deinit(self: *const Tx, alloc: mem.Allocator) void {
        for (self.inputs) |input| {
            alloc.free(input.script_sig);
        }
        alloc.free(self.inputs);

        for (self.outputs) |output| {
            alloc.free(output.script_pubkey);
        }
        alloc.free(self.outputs);

        if (self.witness) |witness| {
            for (witness) |w| {
                alloc.free(w);
            }
            alloc.free(witness);
        }
    }

    fn hashForSigning(self: *const Tx, input_index: usize, hashtype: u8, prev_script_pubkey: []const u8, alloc: mem.Allocator) mem.Allocator.Error!u256 {
        var empty_script = [1]u8{0};
        const tx_copy = tx_copy: {
            var temp: *Tx = try alloc.create(Tx);
            temp.* = self.*;
            temp.outputs = try alloc.dupe(Tx.TxOutput, self.outputs);
            temp.inputs = try alloc.dupe(Tx.TxInput, self.inputs);
            for (0..self.inputs.len) |i| {
                if (i == input_index) {
                    temp.inputs[i].script_sig = try alloc.dupe(u8, prev_script_pubkey);
                } else {
                    temp.inputs[i].script_sig = try alloc.dupe(u8, &empty_script);
                }
            }
            break :tx_copy temp;
        };
        defer {
            for (tx_copy.inputs) |input| alloc.free(input.script_sig);
            alloc.free(tx_copy.outputs);
            alloc.free(tx_copy.inputs);
            alloc.destroy(tx_copy);
        }

        var growing_buffer = try std.ArrayList(u8).initCapacity(alloc, 100);
        var writer_concrete: std.Io.Writer.Allocating = .fromArrayList(alloc, &growing_buffer);
        defer writer_concrete.deinit();

        tx_copy.serialize(&writer_concrete.writer) catch return error.OutOfMemory;
        const tx_copy_bytes = try writer_concrete.toOwnedSlice();

        defer alloc.free(tx_copy_bytes);
        const tx_copy_with_hashtype = try mem.concat(alloc, u8, &[_][]const u8{ tx_copy_bytes, &[4]u8{ hashtype, 0, 0, 0 } });
        defer alloc.free(tx_copy_with_hashtype);
        return double_hash: {
            const hash1 = CryptLib.hashAsU256(tx_copy_with_hashtype);
            var hash1_bytes: [32]u8 = undefined;
            mem.writeInt(u256, &hash1_bytes, hash1, std.builtin.Endian.big);
            break :double_hash CryptLib.hashAsU256(&hash1_bytes);
        };
    }

    pub fn sign(self: *Tx, privkey: u256, input_index: usize, prev_script_pubkey: []const u8, alloc: mem.Allocator) !void {
        const hashtype = 0x01;
        const z = try self.hashForSigning(input_index, hashtype, prev_script_pubkey, alloc);

        // @TODO does not satisfy full BIP141 specification
        const is_witness = for (self.outputs) |o| {
            if (o.script_pubkey.len >= 4 and o.script_pubkey.len <= 42 and o.script_pubkey[0] == 0) {
                break true;
            }
        } else false;
        if (is_witness) {
            self.witness = try alloc.alloc([]u8, 2);
            self.witness.?[0] = witness_signature: {
                var buffer: [72]u8 = undefined;
                const signature = CryptLib.sign(z, privkey).serialize(&buffer);
                const witness_signature = try alloc.alloc(u8, signature.len + 1);
                for (0..signature.len) |i| witness_signature[i] = signature[i];
                witness_signature[72] = hashtype;
                break :witness_signature witness_signature;
            };
            self.witness.?[1] = try alloc.alloc(u8, 33);
            CryptLib.G.muli(privkey).serialize(true, self.witness.?[1][0..33]);
        } else {
            alloc.free(self.inputs[input_index].script_sig);
            self.inputs[input_index].script_sig = resulting_script_sig: {
                var buffer: [72]u8 = undefined;
                const sig = CryptLib.sign(z, privkey).serialize(&buffer);
                const resulting_script_sig_len = 1 + sig.len + 1 + 1 + 33; // <sig.len> <sig> <hashtype> <pubkey_len=33> <pubkey>
                var resulting_script_sig = try alloc.alloc(u8, resulting_script_sig_len);

                // signature
                resulting_script_sig[0] = @intCast(sig.len + 1);
                for (0..sig.len) |i| resulting_script_sig[i + 1] = sig[i];
                resulting_script_sig[sig.len + 1] = hashtype;

                // public key
                resulting_script_sig[sig.len + 2] = 33;
                CryptLib.G.muli(privkey).serialize(true, resulting_script_sig[sig.len + 3 ..][0..33]);

                break :resulting_script_sig resulting_script_sig;
            };
        }
    }

    pub fn checksigSegWit(transaction: *Tx, input_index: usize, script: []const u8) !bool {
        assert(transaction.witness != null);
        assert(transaction.witness.?.len == 2);
        const signature = transaction.witness.?[0];
        const pubkey = transaction.witness.?[1];
        return transaction.checksig(input_index, pubkey, signature, script);
    }

    pub fn checksig(transaction: *const Tx, input_index: usize, pubkey: []const u8, signature: []const u8, script: []const u8, alloc: mem.Allocator) mem.Allocator.Error!bool {
        const hashtype = signature[signature.len - 1];
        const sig = signature[0 .. signature.len - 1];

        const z = try transaction.hashForSigning(input_index, hashtype, script, alloc);
        const pubkey_parsed = EllipticCurveLib.CurvePoint(u256).parse(pubkey, CryptLib.secp256k1_p, CryptLib.G.a, CryptLib.G.b);
        return CryptLib.verify(z, pubkey_parsed, CryptLib.Signature.parse(sig));
    }

    /// Returns a slice owned by the caller
    pub fn serialize(self: *const Tx, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeInt(u32, self.version, .little);

        if (self.witness != null) {
            try writer.writeByte(0);
            try writer.writeByte(1);
        }

        try Util.writeMyVarInt(writer, @intCast(self.inputs.len), .little);
        for (self.inputs) |input| {
            try writer.writeInt(u256, input.txid, .little);
            try writer.writeInt(u32, input.index, .little);
            try Util.writeMyVarInt(writer, @intCast(input.script_sig.len), .little);
            try writer.writeAll(input.script_sig);
            try writer.writeInt(u32, input.sequence, .little);
        }

        try Util.writeMyVarInt(writer, @intCast(self.outputs.len), .little);
        for (self.outputs) |output| {
            try writer.writeInt(u64, output.amount, .little);
            try Util.writeMyVarInt(writer, @intCast(output.script_pubkey.len), .little);
            try writer.writeAll(output.script_pubkey);
        }

        if (self.witness) |witness| {
            try Util.writeMyVarInt(writer, @intCast(witness.len), .little);
            for (witness) |item| {
                try Util.writeMyVarInt(writer, @intCast(item.len), .little);
                try writer.writeAll(item);
            }
        } else {
            // A guy (MrRGnome) told me non-segwit transactions also have witness???
            //try Util.writeVarint(writer, 0);
        }

        try writer.writeInt(u32, self.locktime, .little);
    }

    pub fn parse(reader: *std.Io.Reader, alloc: mem.Allocator) !Tx {
        var tx: Tx = undefined;
        var is_witness = false;

        tx.version = try reader.takeInt(u32, .little);

        tx.inputs = inputs: {
            var n_inputs = try Util.takeMyVarInt(reader, .little);
            if (n_inputs == 0) { // witness marker
                is_witness = true;
                assert(try reader.takeInt(u8, .little) == 1); // witness flag
                n_inputs = try Util.takeMyVarInt(reader, .little);
            }
            const inputs = try alloc.alloc(TxInput, n_inputs);
            for (inputs) |*input| {
                input.txid = try reader.takeInt(u256, .little);
                input.index = try reader.takeInt(u32, .little);
                input.script_sig = script_sig: {
                    const script_sig_len = try Util.takeMyVarInt(reader, .little);
                    const script_sig = try reader.take(@intCast(script_sig_len));
                    break :script_sig try alloc.dupe(u8, script_sig);
                };
                input.sequence = try reader.takeInt(u32, .little);
            }
            break :inputs inputs;
        };

        tx.outputs = outputs: {
            const n_outputs = try Util.takeMyVarInt(reader, .little);
            const outputs = try alloc.alloc(TxOutput, n_outputs);
            for (outputs) |*output| {
                output.amount = try reader.takeInt(u64, .little);
                output.script_pubkey = script_pubkey: {
                    const script_pubkey_len = try Util.takeMyVarInt(reader, .little);
                    const script_pubkey = try reader.take(script_pubkey_len);
                    break :script_pubkey try alloc.dupe(u8, script_pubkey);
                };
            }
            break :outputs outputs;
        };

        tx.witness = witness: {
            if (!is_witness) break :witness null;

            const n_items = try Util.takeMyVarInt(reader, .little);
            const temp_witness = try alloc.alloc([]u8, n_items);
            for (0..n_items) |i| {
                const witness_read_len = try Util.takeMyVarInt(reader, .little);
                const witness_read = try reader.take(witness_read_len);
                temp_witness[i] = try alloc.alloc(u8, witness_read_len);
                std.mem.copyForwards( u8, temp_witness[i], witness_read);
            }
            break :witness temp_witness;
        };

        tx.locktime = try reader.takeInt(u32, .little);

        return tx;
    }

    pub fn isCoinbase(self: *const Tx) bool {
        return self.inputs.len == 1 and
            self.inputs[0].txid == 0 and
            self.inputs[0].index == 0xffffffff;
    }

    pub fn coinbaseBlockHeight(self: *const Tx, alloc: mem.Allocator) !u32 {
        if (!isCoinbase(self)) return error.NotACoinbaseTransaction;
        const script = try Script.parse(self.inputs[0].script_sig, alloc);
        defer script.deinit(alloc);
        std.debug.assert(script.instructions[0] == .data);
        return script.instructions[0].data[0];
    }
};

pub const Script = struct {
    instructions: []const Instruction,

    const Instruction = union(enum) {
        opcode: u8,
        data: []u8,
    };

    pub fn parse(reader: *std.Io.Reader, alloc: mem.Allocator) !Script {
        var instructions = try std.ArrayList(Instruction).initCapacity(alloc, 100);
        defer instructions.deinit(alloc);

        while (reader.takeInt(u8, .little)) |opcode| {
            switch (opcode) {
                0x01...0x4b => { // Data
                    try instructions.append(alloc, .{
                        .data = try alloc.dupe(u8, try reader.take(@intCast(opcode))),
                    });
                },
                else => {
                    if (!Opcode.isSupported(opcode)) return error.OpcodeNotSupported;
                    try instructions.append(alloc, .{ .opcode = opcode });
                },
            }
        } else |err| switch(err) {
            error.EndOfStream => {},
            error.ReadFailed => unreachable,
        }

        return Script{
            .instructions = try instructions.toOwnedSlice(alloc),
        };
    }

    pub fn deinit(self: Script, alloc: mem.Allocator) void {
        for (self.instructions) |inst| {
            switch (inst) {
                .data => |d| alloc.free(d),
                .opcode => {},
            }
        }
        alloc.free(self.instructions);
    }

    const Stack = struct {
        data: []u8,

        /// Points to first empty index
        top: usize = 0,

        /// null alloc means the stack is not allowed to grow implicitly
        alloc: ?mem.Allocator = null,

        const MAX_STACK_ELEMENT_SIZE: usize = 520;

        ///Same behaviour as Bitcoin Core:
        ///   "Numeric opcodes (OP_ADD, etc) are restricted to operating on 4-byte integers.
        ///    The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
        ///    but results may overflow (and are valid as long as they are not used in a subsequent
        ///    numeric operation). CScriptNum enforces those semantics by storing results as
        ///    an int64 and allowing out-of-range values to be returned as a vector of bytes but
        ///    throwing an exception if arithmetic is done or the result is interpreted as an integer."
        const Int = i64;

        const Self = @This();

        fn init(size: usize, alloc: mem.Allocator) !Self {
            return .{ .data = try alloc.alloc(u8, size) };
        }

        fn deinit(self: *const Self, alloc: mem.Allocator) void {
            alloc.free(self.data);
        }

        /// Calling this function means the stack will be able to grow implicitly when pushing more than bytes than it fits
        fn setAlloc(self: *Self, alloc: mem.Allocator) void {
            self.alloc = alloc;
        }

        /// Can call realloc implicitly if self.alloc != null
        fn push(self: *Self, value: []const u8) PushError!void {
            while (self.top + value.len > self.data.len) {
                if (self.alloc == null) return error.StackFull; // not allowed to realloc
                self.data = try self.alloc.?.realloc(self.data, self.data.len * 2);
            }
            mem.copyForwards(u8, self.data[self.top..][0..value.len], value);
            self.top += value.len;
            if (value.len > std.math.maxInt(u8))
                @panic("Not handling this case yet: pushing more than 255 bytes");
            self.data[self.top] = @intCast(value.len);
            self.top += 1;
        }
        const PushError = error{StackFull} || mem.Allocator.Error;

        fn pushInt(self: *Self, value: Self.Int) PushError!void {
            try self.push(mem.asBytes(&value));
        }

        /// Currently doesn't realloc to shrink
        fn pop(self: *Self, buffer: []u8) PopError![]u8 {
            if (self.top == 0)
                return PopError.EmptyStack;
            self.top -= 1;
            const next_byte = self.data[self.top];
            if (self.data.len < next_byte)
                return PopError.Corrupted;
            if (next_byte == 0)
                return &[_]u8{};
            if (next_byte > buffer.len)
                return PopError.OutBufferTooSmall;
            const ret = self.data[self.top - next_byte .. self.top];
            mem.copyForwards(u8, buffer[0..next_byte], ret);
            self.top -= next_byte;
            return buffer[0..next_byte];
        }
        const PopError = error{ EmptyStack, Corrupted, OutBufferTooSmall };

        fn popInt(self: *Self) error{ EmptyStack, Corrupted, NotAnOperableInteger }!Self.Int {
            var buffer_data: [4]u8 = undefined;
            const data = self.pop(&buffer_data) catch |err| return switch (err) {
                PopError.OutBufferTooSmall => error.Corrupted,
                PopError.EmptyStack => error.EmptyStack,
                PopError.Corrupted => error.Corrupted,
            };
            if (data.len > 4) {
                return error.NotAnOperableInteger;
            } else if (data.len == 4) {
                const data_as_unsigned = mem.readInt(u32, data[0..4], .big);
                const sign_as_int: Self.Int = if (data_as_unsigned & 0x80000000 != 0) -1 else 1;
                const value: Self.Int = (data_as_unsigned & 0x7FFFFFFF);

                return sign_as_int * value;
            } else if (data.len == 1) {
                // when less than 4 bytes, the value can't be signed
                return @as(Self.Int, @intCast(data[0]));
            } else {
                // TODO
                @panic("Not handling this case yet: popping more than 1 but less than 4 bytes");
            }
        }

        /// Only false when top value is existent AND not true.
        /// Zero, negative zero and empty array are all treated as false.
        /// Anything else is treated as true.
        fn verify(self: *Stack) bool {
            var buffer_value: [MAX_STACK_ELEMENT_SIZE]u8 = undefined;
            const value = self.pop(&buffer_value) catch |err| return err == error.EmptyStack;
            const all_zero = for (value, 0..) |byte, index| {
                if (index == value.len - 1 and byte == 0x80) continue; // account for negative zero
                if (byte != 0) break false;
            } else true;
            if (value.len == 0 or all_zero) {
                return false;
            }
            return true;
        }
    };

    // This must not be an enum. An enum is a type. I want constants of type u8. Which means this struct serves only as a namespace
    pub const Opcode = struct {
        pub const OP_0: u8 = 0;
        pub const OP_PUSHDATA1: u8 = 0x4c;
        pub const OP_PUSHDATA2: u8 = 0x4d;
        pub const OP_PUSHDATA4: u8 = 0x4e;
        pub const OP_1: u8 = 0x51;
        pub const OP_2: u8 = 0x52;
        pub const OP_3: u8 = 0x53;
        pub const OP_4: u8 = 0x54;
        pub const OP_5: u8 = 0x55;
        pub const OP_6: u8 = 0x56;
        pub const OP_7: u8 = 0x57;
        pub const OP_8: u8 = 0x58;
        pub const OP_9: u8 = 0x59;
        pub const OP_10: u8 = 0x5a;
        pub const OP_11: u8 = 0x5b;
        pub const OP_12: u8 = 0x5c;
        pub const OP_13: u8 = 0x5d;
        pub const OP_14: u8 = 0x5e;
        pub const OP_15: u8 = 0x5f;
        pub const OP_16: u8 = 0x60;
        pub const OP_VERIFY: u8 = 0x69;
        pub const OP_2DUP: u8 = 0x6e;
        pub const OP_DUP: u8 = 0x76;
        pub const OP_EQUAL: u8 = 0x87;
        pub const OP_EQUALVERIFY: u8 = 0x88;
        pub const OP_NOT: u8 = 0x91;
        pub const OP_ADD: u8 = 0x93;
        pub const OP_SUB: u8 = 0x94;
        pub const OP_SHA256: u8 = 0xa8;
        pub const OP_HASH160: u8 = 0xa9;
        pub const OP_CHECKSIG: u8 = 0xac;

        pub fn isSupported(opcode: u8) bool {
            if (opcode < OP_16) return true;

            const values_supported = comptime res: {
                var res = [_]u8{0} ** 60;
                var next: usize = 0;
                for (@typeInfo(Opcode).@"struct".decls) |decl| {
                    const value = @field(Opcode, decl.name);
                    if (@TypeOf(value) != u8) continue;
                    res[next] = value;
                    next += 1;
                }
                break :res res;
            };

            return for (values_supported) |value| {
                if (value == opcode) break true;
            } else false;
        }
    };

    const RunError = mem.Allocator.Error || error{
        Internal,
        BadScript,
        StackFull,
        VerifyFailed,
    };
    pub fn run(script: []const u8, stack: *Stack, transaction: ?*Tx, input_index: ?usize, alloc: mem.Allocator) RunError!void {
        var script_reader: std.Io.Reader = .fixed(script);
        const Op = Opcode;
        const Local = struct {
            fn handlePopError(err: Stack.PopError) !void {
                return switch (err) {
                    error.OutBufferTooSmall => error.Internal,
                    error.Corrupted, error.EmptyStack => error.BadScript,
                };
            }

            fn handleReaderError(err: std.Io.Reader.Error) !void {
                return switch (err) {
                    error.ReadFailed => unreachable,
                    error.EndOfStream => error.Internal,
                };
            }
        };

        while (script_reader.takeInt(u8, .little)) |opcode| {
            switch (opcode) {
                0x01...0x4b => { // Data
                    const data = script_reader.take(@intCast(opcode)) catch |err| return Local.handleReaderError(err);
                    try stack.push(data);
                },
                Op.OP_0 => {
                    try stack.push(&[_]u8{});
                },
                Op.OP_1...Op.OP_16 => { // OP_1 to OP_16
                    try stack.push(&[1]u8{opcode - 0x50});
                },
                Op.OP_PUSHDATA1 => {
                    const size = script_reader.takeInt(u8, .little) catch |err| return Local.handleReaderError(err);
                    const data = script_reader.take(@intCast(size)) catch |err| return Local.handleReaderError(err);
                    try stack.push(data);
                },
                Op.OP_VERIFY => {
                    if (!stack.verify())
                        return error.VerifyFailed;
                },
                Op.OP_2DUP => {
                    var buffer_a: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    var buffer_b: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const a = stack.pop(&buffer_a) catch |err| return Local.handlePopError(err);
                    const b = stack.pop(&buffer_b) catch |err| return Local.handlePopError(err);
                    try stack.push(a);
                    try stack.push(b);
                    try stack.push(a);
                    try stack.push(b);
                },
                Op.OP_DUP => {
                    var buffer_value: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const value = stack.pop(&buffer_value) catch |err| return Local.handlePopError(err);
                    try stack.push(value);
                    try stack.push(value);
                },
                Op.OP_EQUAL => {
                    var buffer_a: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    var buffer_b: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const a = stack.pop(&buffer_a) catch |err| return Local.handlePopError(err);
                    const b = stack.pop(&buffer_b) catch |err| return Local.handlePopError(err);
                    const eq: u8 = if (mem.eql(u8, a, b)) 1 else 0;
                    try stack.push(&[1]u8{eq});
                },
                Op.OP_EQUALVERIFY => {
                    var buffer_a: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    var buffer_b: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const a = stack.pop(&buffer_a) catch |err| return Local.handlePopError(err);
                    const b = stack.pop(&buffer_b) catch |err| return Local.handlePopError(err);
                    if (!mem.eql(u8, a, b)) {
                        return error.VerifyFailed;
                    }
                },
                Op.OP_NOT => {
                    var buffer_value: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const value = stack.pop(&buffer_value) catch |err| return Local.handlePopError(err);
                    const equals_zero: u8 = for (value) |byte| {
                        if (byte != 0) break 0;
                    } else 1;
                    try stack.push(&[1]u8{equals_zero});
                },
                Op.OP_ADD => {
                    const a: i64 = stack.popInt() catch return error.BadScript;
                    const b: i64 = stack.popInt() catch return error.BadScript;
                    const value: i64 = a + b;
                    try stack.pushInt(value);
                },
                Op.OP_SUB => {
                    const a: i64 = stack.popInt() catch return error.BadScript;
                    const b: i64 = stack.popInt() catch return error.BadScript;
                    const value: i64 = a - b;
                    try stack.pushInt(value);
                },
                Op.OP_SHA256 => {
                    var buffer_value: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const value = stack.pop(&buffer_value) catch |err| return Local.handlePopError(err);
                    var value_hash: [32]u8 = undefined;
                    Sha256.hash(value, &value_hash, .{});
                    try stack.push(&value_hash);
                },
                Op.OP_HASH160 => {
                    var buffer_value: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const value = stack.pop(&buffer_value) catch |err| return switch (err) {
                        Stack.PopError.OutBufferTooSmall => @panic("Not handling HASH160 for stack items larger than 520 bytes"),
                        else => Local.handlePopError(err),
                    };
                    var hash160_data: [20:0]u8 = @splat(undefined);
                    hash160(value, &hash160_data);
                    try stack.push(&hash160_data);
                },
                Op.OP_CHECKSIG => {
                    if (transaction == null) @panic("Trying to execute OP_CHECKSIG with a null transaction");
                    if (input_index == null) @panic("Trying to execute OP_CHECKSIG with a null input_index");
                    var buffer_pubkey: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    var buffer_signature: [Stack.MAX_STACK_ELEMENT_SIZE]u8 = undefined;
                    const pubkey = stack.pop(&buffer_pubkey) catch |err| return Local.handlePopError(err);
                    const signature = stack.pop(&buffer_signature) catch |err| return Local.handlePopError(err);
                    if (try Tx.checksig(transaction.?, input_index.?, pubkey, signature, script, alloc)) {
                        try stack.push(&[1]u8{1});
                    } else {
                        try stack.push(&[1]u8{0});
                    }
                },
                else => {
                    var buffer: [100]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buffer, "Opcode {} not implemented\n", .{opcode}) catch @panic("While running a Script, a not implemented Opcode was found");
                    @panic(msg);
                },
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            error.ReadFailed => unreachable,
        }
    }

    pub const Error = error{Internal} || mem.Allocator.Error;
    pub fn validate(scriptSig: []const u8, scriptPubKey: []const u8, transaction: ?*Tx, input_index: ?usize, alloc: mem.Allocator) Error!bool {
        var stack = try Stack.init(scriptSig.len + scriptPubKey.len, alloc);
        defer stack.deinit(alloc);
        stack.setAlloc(alloc);

        const Local = struct {
            fn handleError(err: Script.RunError) !bool {
                return switch (err) {
                    error.Internal, error.StackFull => error.Internal,
                    mem.Allocator.Error.OutOfMemory => error.OutOfMemory,
                    error.BadScript, error.VerifyFailed => false,
                };
            }
        };

        Script.run(scriptSig, &stack, transaction, input_index, alloc) catch |err| return Local.handleError(err);
        Script.run(scriptPubKey, &stack, transaction, input_index, alloc) catch |err| return Local.handleError(err);

        return stack.verify();
    }
};

pub const Block = struct {
    version: u32 = 0x20000002,
    /// Always stored in big endian (leading 0s)
    prev_block: [32]u8,
    /// Always stored in big endian
    merkle_root: [32]u8,
    /// in seconds
    timestamp: u32,
    bits: u32,
    nonce: u32,

    /// Returns a slice to the written bytes
    pub fn serialize(self: *const Block, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeInt(u32, self.version, .little);
        for (0..32) |i| try writer.writeByte(self.prev_block[31 - i]);
        for (0..32) |i| try writer.writeByte(self.merkle_root[31 - i]);
        try writer.writeInt(u32, self.timestamp, .little);
        try writer.writeInt(u32, self.bits, .little);
        try writer.writeInt(u32, self.nonce, .big);
        //std.debug.assert(writer.end == 80);
    }

    /// Expects 80 bytes and panics otherwise
    pub fn parse(reader: *std.Io.Reader) Block {
        const panic = struct {
            pub fn panic() noreturn { std.debug.panic("Expected a reader with 80 bytes remaining", .{}); }
        }.panic;
        var block: Block = undefined;
        block.version = reader.takeInt(u32, .little) catch panic();
        for (0..32) |i| block.prev_block[31 - i] = reader.takeInt(u8, .little) catch panic();
        for (0..32) |i| block.merkle_root[31 - i] = reader.takeInt(u8, .little) catch panic();
        block.timestamp = reader.takeInt(u32, .little) catch panic();
        block.bits = reader.takeInt(u32, .little) catch panic();
        block.nonce = reader.takeInt(u32, .big) catch panic();
        return block;
    }

    /// Resulting bytes on `buffer` should be read as big-endian. `buffer` should have at least 32 bytes
    pub fn hash(self: *const Block, buffer: []u8) void {
        std.debug.assert(buffer.len >= 32);
        var block_buffer: [80]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&block_buffer);
        self.serialize(&writer) catch unreachable;
        var intermediate_buffer1: [32]u8 = undefined;
        Sha256.hash(&block_buffer, intermediate_buffer1[0..32], .{});
        Sha256.hash(intermediate_buffer1[0..32], buffer[0..32], .{});
        mem.reverse(u8, buffer[0..32]);
    }

    pub fn bitsToTarget(bits: u32) u256 {
        var as_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &as_bytes, bits, .big);
        const exponent = as_bytes[0];
        std.debug.assert(exponent <= 32);
        const coefficient = mem.readInt(u24, as_bytes[1..4], .big);
        return @as(u256, coefficient) << (8 * (exponent - 3));
    }

    pub fn targetToBits(target: u256) u32 {
        var as_bytes: [32]u8 = undefined;
        mem.writeInt(u256, &as_bytes, target, .big);
        const trimmed = mem.trimLeft(u8, &as_bytes, &[1]u8{0});
        var exponent: u8 = undefined;
        var coefficient: [3]u8 = undefined;
        if ((trimmed[0] & 0b1000_0000) != 0) {
            exponent = @intCast(trimmed.len + 1);
            coefficient = [1]u8{0x00} ++ mem.bytesAsValue([2]u8, trimmed[0..2]).*;
        } else {
            exponent = @intCast(trimmed.len);
            coefficient = mem.bytesAsValue([3]u8, trimmed[0..3]).*;
        }
        const new_bits = [1]u8{exponent} ++ coefficient;
        return mem.readInt(u32, &new_bits, .big);
    }

    /// expects `time_diff`, in seconds, calculated as `last timestamp of DA-period` - `first`
    pub fn calculateNewBits(previous_bits: u32, time_diff: u32) u32 {
        // This is the target with the minimal network difficulty
        const max_target = 0x00000000ffff0000000000000000000000000000000000000000000000000000;
        const two_weeks = 2 * 7 * 24 * 60 * 60; // in seconds
        var valid_time_diff = time_diff;
        if (time_diff > two_weeks * 4) {
            valid_time_diff = two_weeks * 4;
        } else if (time_diff < @divExact(two_weeks, 4)) {
            valid_time_diff = @divExact(two_weeks, 4);
        }
        //std.debug.print("valid_time_diff: {d}\n", .{ valid_time_diff });
        //std.debug.print("expected: {d}\n", .{ two_weeks });
        //std.debug.print("valid_time_diff/expected: {d}\n", .{ @as(f32, @floatFromInt(valid_time_diff)) / two_weeks });
        //std.debug.print("old_bits: {x:0>8}\n", .{ previous_bits });
        //std.debug.print("old_target: {x:0>64}\n", .{ Block.bitsToTarget(previous_bits) });
        var new_target: u256 = @divFloor(Block.bitsToTarget(previous_bits) * valid_time_diff, @as(u256, two_weeks));
        if (new_target > max_target) new_target = max_target;
        //std.debug.print("new_target: {x:0>64}\n", .{ new_target });
        const new_bits = Block.targetToBits(new_target);
        //std.debug.print("new_bits: {x:0>8}\n", .{ new_bits });
        return new_bits;
    }

    pub fn checkProofOfWork(self: *const Block) bool {
        var hash_value: [32]u8 = undefined;
        self.hash(&hash_value);
        return mem.readInt(u256, &hash_value, .big) < Block.bitsToTarget(self.bits);
    }
};

//#region TESTS #########################################################################

const expect = std.testing.expect;
const t_alloc = std.testing.allocator;

test "base58: encoding and decoding" {
    { // array/slice directly
        const u8_array = [8]u8{ 0x00, 0x00, 0x04, 0x09, 0x0a, 0x0f, 0x1a, 0xff };
        var buf: [10]u8 = undefined;
        const encoded_u8_array = Base58.encode(&u8_array, &buf);
        try expect(mem.eql(u8, encoded_u8_array, "31Yr1PVY"));

        var decoding_buffer: [128]u8 = undefined;
        const decoded = Base58.decode(encoded_u8_array, &decoding_buffer);
        try expect(mem.eql(u8, decoded, u8_array[2..]));
    }

    { // number gets written as big endian
        const number: u256 = 0xf45e6907b16670196e487cf667e9fa510f0593276335da22311eb67c90d46421;
        var number_bytes: [32]u8 = undefined;
        mem.writeInt(u256, &number_bytes, number, .big);
        var buf: [128]u8 = undefined;
        const encoded = Base58.encode(&number_bytes, &buf);
        try std.testing.expectEqualStrings("HSuyZVztYLpebSGXgjP5vaF4xZFxac8nXQY2m7QGSrVn", encoded);

        var decoding_buffer: [128]u8 = undefined;
        const decoded = Base58.decode(encoded, &decoding_buffer);
        try expect(mem.eql(u8, &number_bytes, decoded));
    }
}

test "address:" {
    const prvk = 0x5da1cb5b4282e3f5c2314df81a3711fa7f0217401de5f72da0ab4906fab04f4c;
    var buf: [40]u8 = undefined;
    const address = Address.fromPrivkey(prvk, false, &buf);
    try expect(mem.eql(u8, address, "1GHqmiofmT3PgrZDf7fcq632xybfg6onG4"));
}

test "tx: parse and serialize p2pkh transaction" {
    // zig fmt: off
    var transaction_bytes = [_]u8{
        0x01, 0x00, 0x00, 0x00, // version (constant)
        0x01, // number of inputs
            // 32 bytes of TXID
            0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80, 0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03, 0x98, 0xa1, 0x4f, 0x3f,
            0x00, 0x00, 0x00, 0x00, // output index
            0x49, // bytes of script signature
                0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad, 0x2b, 0x5e, 0xb3, 0x99, 0xd5, 0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96, 0xdf, 0x1a, 0x71, 0x50, 0xde, 0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65, 0x60, 0x90, 0xd7, 0xf6, 0xba, 0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42, 0x68, 0xe0, 0x82, 0xa7, 0x25, 0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86, 0x6a, 0x5f, 0x01,
            0xff, 0xff, 0xff, 0xff, // sequence
        0x01, // number of outputs
            0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // amount
            0x19, // bytes of script pubkey
                0x76, 0xa9, 0x14, 0xcb, 0xc2, 0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa, 0x42, 0x70, 0x45, 0xbc, 0x15, 0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
        0x00, 0x00, 0x00, 0x00 // locktime
    };
    // zig fmt: on
    var reader: std.Io.Reader = .fixed(transaction_bytes[0..transaction_bytes.len]);
    const transaction = try Tx.parse(&reader, t_alloc);
    defer transaction.deinit(t_alloc);

    var growing_buffer = try std.ArrayList(u8).initCapacity(t_alloc, 100);
    var writer_concrete: std.Io.Writer.Allocating = .fromArrayList(t_alloc, &growing_buffer);
    defer writer_concrete.deinit();

    transaction.serialize(&writer_concrete.writer) catch return error.OutOfMemory;
    const serialized = try writer_concrete.toOwnedSlice();
    defer t_alloc.free(serialized);
    try std.testing.expectEqualSlices(u8, transaction_bytes[0..transaction_bytes.len], serialized);
}

test "tx: parse p2wpkh transaction" {
    // zig fmt: off
    var transaction_bytes = [_]u8{
        0x02, 0x00, 0x00, 0x00,
        0x00, 0x01, // witness marker and flag
        0x01,
            0x28, 0xae, 0x67, 0x25, 0x22, 0x1f, 0xc3, 0x11, 0x91, 0x26, 0x09, 0xd2, 0xc3, 0x43, 0x50, 0x0f, 0x63, 0x35, 0x10, 0x65, 0xab, 0x59, 0xca, 0xf5, 0xc3, 0x16, 0x38, 0x66, 0x21, 0x77, 0xea, 0xdc,
            0x01, 0x00, 0x00, 0x00,
            0x00,
            0xfd, 0xff, 0xff, 0xff,
        0x02,
            0x19, 0xcf, 0x0b, 0x44, 0x3a, 0x00, 0x00, 0x00,
            0x22,   0x51, 0x20, 0xaa, 0xc3, 0x5f, 0xe9, 0x1f, 0x20, 0xd4, 0x88, 0x16, 0xb3, 0xc8, 0x30, 0x11, 0xd1, 0x17, 0xef, 0xa3, 0x5a, 0xcd, 0x24, 0x14, 0xd3, 0x6c, 0x1e, 0x02, 0xb0, 0xf2, 0x9f, 0xc3, 0x10, 0x6d, 0x90,

            0x80, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x16,   0x00, 0x14, 0xbf, 0x9d, 0x74, 0xa5, 0x0e, 0x3b, 0x9c, 0x9a, 0xca, 0x37, 0x08, 0xca, 0x95, 0x14, 0x19, 0xbb, 0xd6, 0xfa, 0x32, 0x63,
        // witness
        0x01, 0x40, 0x66, 0xbb, 0xff, 0xd4, 0xda, 0xfd, 0x01, 0x72, 0x83, 0xa7, 0x13, 0x2e, 0xff, 0x9f, 0x70, 0xf1, 0xec, 0xbc, 0x5c, 0x66, 0x38, 0xc3, 0x1b, 0x75, 0x6e, 0x61, 0xa6, 0xa6, 0x3e, 0x07, 0x2f, 0xe6, 0xf5, 0x4a, 0xc4, 0xfd, 0x69, 0xa4, 0x06, 0x10, 0xdf, 0x05, 0xef, 0xbf, 0x08, 0xa7, 0x3b, 0xb5, 0x85, 0x22, 0x7c, 0xd7, 0x5d, 0x99, 0xb5, 0xa8, 0xd3, 0x54, 0x1b, 0xc1, 0x04, 0xe5, 0x10, 0x50,
        0x00, 0x00, 0x00, 0x00 // locktime
    };
    // zig fmt: on
    var reader: std.Io.Reader = .fixed(transaction_bytes[0..transaction_bytes.len]);
    const transaction = try Tx.parse(&reader, t_alloc);
    defer transaction.deinit(t_alloc);
    try expect(transaction.inputs.len == 1);
    try expect(transaction.outputs.len == 2);
    try expect(transaction.outputs[1].amount == 6272);
}

test "script: Opcode.isSupported" {
    const Op = Script.Opcode;
    try expect(Op.isSupported(0) == true);
    try expect(Op.isSupported(0x50) == true);
    try expect(Op.isSupported(Op.OP_VERIFY) == true);
    try expect(Op.isSupported(Op.OP_EQUAL) == true);
    try expect(Op.isSupported(0xcf) == false);
}

test "script: Script parsing" {
    const Op = Script.Opcode;
    const script_bytes = [34]u8{ Op.OP_1, 0x20, 0xaa, 0xc3, 0x5f, 0xe9, 0x1f, 0x20, 0xd4, 0x88, 0x16, 0xb3, 0xc8, 0x30, 0x11, 0xd1, 0x17, 0xef, 0xa3, 0x5a, 0xcd, 0x24, 0x14, 0xd3, 0x6c, 0x1e, 0x02, 0xb0, 0xf2, 0x9f, 0xc3, 0x10, 0x6d, 0x90 };
    var reader: std.Io.Reader = .fixed(&script_bytes);
    const script = try Script.parse(&reader, t_alloc);
    defer script.deinit(t_alloc);
    try expect(script.instructions.len == 2);
    try expect(script.instructions[0].opcode == Op.OP_1);
    try expect(script.instructions[1].data.len == 32);
    try std.testing.expectEqualSlices(u8, script_bytes[2..34], script.instructions[1].data);
}

test "script: Basic script execution" {
    const answer = "And he answering said, Thou shalt love the Lord thy God with all thy heart, and with all thy soul, and with all thy strength, and with all thy mind; and thy neighbour as thyself.";
    const answer_hash = answer_hash: {
        var buf: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(answer, &buf, .{});
        break :answer_hash buf;
    };
    const Op = Script.Opcode;
    const script_pub_key = [_]u8{Op.OP_SHA256} ++ [1]u8{answer_hash.len} ++ answer_hash ++ [_]u8{ Op.OP_EQUAL, Op.OP_VERIFY };
    const script_sig = [_]u8{Op.OP_PUSHDATA1} ++ [1]u8{answer.len} ++ answer.*;
    try expect(try Script.validate(&script_sig, &script_pub_key, null, null, t_alloc));
}

test "tx: transaction signing and checksig" {
    const privkey = 0xf45e6907b16670196e487cf667e9fa510f0593276335da22311eb67c90d46421;
    const pubk = CryptLib.G.muli(privkey);
    var pubk_serialized: [33]u8 = undefined;
    pubk.serialize(true, &pubk_serialized);
    const prev_txid = 0x38067470a9a51bea07c1f8b7f51d75d521b57ca9c9d1bf68a2467efe79971fd2;
    const prev_script_pubkey = [_]u8{ 0x76, 0xa9, 0x14, 0xaf, 0x72, 0x4f, 0xc6, 0x1f, 0x4d, 0x5c, 0x4d, 0xb0, 0x6b, 0x33, 0x95, 0xc9, 0xb4, 0x50, 0xa8, 0x0d, 0x25, 0xb6, 0x73, 0x88, 0xac };
    const target_address = "mnvfTUzPbeWBxwxinm37C1bsQ5ckZuN9E7";

    var transaction = try Tx.initP2PKH(.{
        .testnet = true,
        .prev_txid = prev_txid,
        .prev_output_index = 1,
        .amount = 5000,
        .target_address = target_address,
        .alloc = t_alloc,
    });
    defer transaction.deinit(t_alloc);

    try transaction.sign(privkey, 0, &prev_script_pubkey, t_alloc);

    // CHECKSIG Verifying
    const checksig = try Tx.checksig(
        &transaction,
        0,
        &pubk_serialized,
        transaction.inputs[0].script_sig[1..][0..(transaction.inputs[0].script_sig[0])],
        //transaction.witness.?[0], // or above
        &prev_script_pubkey,
        t_alloc,
    );

    try std.testing.expect(checksig);
}

test "block: isCoinbase" {
    const tx_bytes = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x5e, 0x03, 0xd7, 0x1b, 0x07, 0x25, 0x4d, 0x69, 0x6e, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x41, 0x6e, 0x74, 0x50, 0x6f, 0x6f, 0x6c, 0x20, 0x62, 0x6a, 0x31, 0x31, 0x2f, 0x45, 0x42, 0x31, 0x2f, 0x41, 0x44, 0x36, 0x2f, 0x43, 0x20, 0x59, 0x14, 0x29, 0x31, 0x01, 0xfa, 0xbe, 0x6d, 0x6d, 0x67, 0x8e, 0x2c, 0x8c, 0x34, 0xaf, 0xc3, 0x68, 0x96, 0xe7, 0xd9, 0x40, 0x28, 0x24, 0xed, 0x38, 0xe8, 0x56, 0x67, 0x6e, 0xe9, 0x4b, 0xfd, 0xb0, 0xc6, 0xc4, 0xbc, 0xd8, 0xb2, 0xe5, 0x66, 0x6a, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x27, 0x00, 0x00, 0xa5, 0xe0, 0x0e, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0xfa, 0xf2, 0x0b, 0x58, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0x33, 0x8c, 0x84, 0x84, 0x94, 0x23, 0x99, 0x24, 0x71, 0xbf, 0xfb, 0x1a, 0x54, 0xa8, 0xd9, 0xb1, 0xd6, 0x9d, 0xc2, 0x8a, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00 };
    var reader: std.Io.Reader = .fixed(&tx_bytes);
    const tx = try Tx.parse(&reader, t_alloc);
    defer tx.deinit(t_alloc);
    try expect(tx.isCoinbase() == true);
}

test "block: Block parse" {
    const block_raw = [_]u8{ 0x02, 0x00, 0x00, 0x20, 0x8e, 0xc3, 0x94, 0x28, 0xb1, 0x73, 0x23, 0xfa, 0x0d, 0xde, 0xc8, 0xe8, 0x87, 0xb4, 0xa7, 0xc5, 0x3b, 0x8c, 0x0a, 0x0a, 0x22, 0x0c, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x07, 0x50, 0xfc, 0xe0, 0xa8, 0x89, 0x50, 0x2d, 0x40, 0x50, 0x8d, 0x39, 0x57, 0x68, 0x21, 0x15, 0x5e, 0x9c, 0x9e, 0x3f, 0x5c, 0x31, 0x57, 0xf9, 0x61, 0xdb, 0x38, 0xfd, 0x8b, 0x25, 0xbe, 0x1e, 0x77, 0xa7, 0x59, 0xe9, 0x3c, 0x01, 0x18, 0xa4, 0xff, 0xd7, 0x1d };
    var reader: std.Io.Reader = .fixed(&block_raw);
    const block = Block.parse(&reader);
    try expect(block.version == 0x20000002);
    const expected_prev_block = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x0c, 0x22, 0x0a, 0x0a, 0x8c, 0x3b, 0xc5, 0xa7, 0xb4, 0x87, 0xe8, 0xc8, 0xde, 0x0d, 0xfa, 0x23, 0x73, 0xb1, 0x28, 0x94, 0xc3, 0x8e };
    try std.testing.expectEqualSlices(u8, &expected_prev_block, &block.prev_block);
    const expected_merkle_root = [_]u8{ 0xbe, 0x25, 0x8b, 0xfd, 0x38, 0xdb, 0x61, 0xf9, 0x57, 0x31, 0x5c, 0x3f, 0x9e, 0x9c, 0x5e, 0x15, 0x21, 0x68, 0x57, 0x39, 0x8d, 0x50, 0x40, 0x2d, 0x50, 0x89, 0xa8, 0xe0, 0xfc, 0x50, 0x07, 0x5b };
    try std.testing.expectEqualSlices(u8, &expected_merkle_root, &block.merkle_root);
    try expect(block.timestamp == 1504147230);
    try expect(block.bits == 0x18013ce9);
    try expect(block.nonce == 0xa4ffd71d);
}

test "block: Block serialize" {
    {
        const block_raw = [_]u8{ 0x02, 0x00, 0x00, 0x20, 0x8e, 0xc3, 0x94, 0x28, 0xb1, 0x73, 0x23, 0xfa, 0x0d, 0xde, 0xc8, 0xe8, 0x87, 0xb4, 0xa7, 0xc5, 0x3b, 0x8c, 0x0a, 0x0a, 0x22, 0x0c, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x07, 0x50, 0xfc, 0xe0, 0xa8, 0x89, 0x50, 0x2d, 0x40, 0x50, 0x8d, 0x39, 0x57, 0x68, 0x21, 0x15, 0x5e, 0x9c, 0x9e, 0x3f, 0x5c, 0x31, 0x57, 0xf9, 0x61, 0xdb, 0x38, 0xfd, 0x8b, 0x25, 0xbe, 0x1e, 0x77, 0xa7, 0x59, 0xe9, 0x3c, 0x01, 0x18, 0xa4, 0xff, 0xd7, 0x1d };
        var reader: std.Io.Reader = .fixed(&block_raw);
        var block = Block.parse(&reader);
        var buffer: [80]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try block.serialize(&writer);
        try std.testing.expectEqualSlices(u8, &block_raw, &buffer);
    }
    {
        var block = @import("blockchain.zig").genesis_block;
        var buffer: [80]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try block.serialize(&writer);
        try std.testing.expectEqualSlices(u8,
            &[_]u8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x1d, 0xac, 0x2b, 0x7c },
            &buffer,
        );
    }
}

test "block: Block hash" {
    {
        var block = @import("blockchain.zig").genesis_block;
        var hash: [32]u8 = undefined;
        block.hash(&hash);
        try std.testing.expectEqualSlices(u8,
            &[_]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f },
            &hash,
        );
        try expect(block.checkProofOfWork());
    }
    {
        const block_raw = [_]u8{ 0x02, 0x00, 0x00, 0x20, 0x8e, 0xc3, 0x94, 0x28, 0xb1, 0x73, 0x23, 0xfa, 0x0d, 0xde, 0xc8, 0xe8, 0x87, 0xb4, 0xa7, 0xc5, 0x3b, 0x8c, 0x0a, 0x0a, 0x22, 0x0c, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x07, 0x50, 0xfc, 0xe0, 0xa8, 0x89, 0x50, 0x2d, 0x40, 0x50, 0x8d, 0x39, 0x57, 0x68, 0x21, 0x15, 0x5e, 0x9c, 0x9e, 0x3f, 0x5c, 0x31, 0x57, 0xf9, 0x61, 0xdb, 0x38, 0xfd, 0x8b, 0x25, 0xbe, 0x1e, 0x77, 0xa7, 0x59, 0xe9, 0x3c, 0x01, 0x18, 0xa4, 0xff, 0xd7, 0x1d };
        var reader: std.Io.Reader = .fixed(&block_raw);
        var block = Block.parse(&reader);
        var hash: [32]u8 = undefined;
        block.hash(&hash);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x9e, 0x4c, 0x58, 0x64, 0x39, 0xb0, 0xcd, 0xbe, 0x13, 0xb1, 0x37, 0x0b, 0xdd, 0x94, 0x35, 0xd7, 0x6a, 0x64, 0x4d, 0x04, 0x75, 0x23 }, &hash);
        try expect(block.checkProofOfWork());
    }
}

test "block: bits to target and back" {
    {
        const bits = 0x1d00ffff;
        const target = Block.bitsToTarget(bits);
        try expect(target == 0x00000000ffff0000000000000000000000000000000000000000000000000000);
        try expect(Block.targetToBits(target) == 0x1d00ffff);
    }
    {
        const bits = 0x18013ce9;
        const target = Block.bitsToTarget(bits);
        try expect(target == 0x0000000000000000013ce9000000000000000000000000000000000000000000);
        try expect(Block.targetToBits(target) == 0x18013ce9);
    }
    {
        const bits = 0x04b3011e;
        const target = Block.bitsToTarget(bits);
        try expect(target == 0x00000000000000000000000000000000000000000000000000000000b3011e00);
        try expect(Block.targetToBits(target) == 0x0500b301);
    }
}

test "block: calculate new bits" {
    {
        // Block 471744
        const first_raw = [_]u8{ 0x00, 0x00, 0x00, 0x20, 0x34, 0x71, 0x10, 0x1b, 0xbd, 0xa3, 0xfe, 0x30, 0x76, 0x64, 0xb3, 0x28, 0x3a, 0x9e, 0xf0, 0xe9, 0x7d, 0x9a, 0x38, 0xa7, 0xea, 0xcd, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xc8, 0xab, 0xa8, 0x47, 0x9b, 0xba, 0xa5, 0xe0, 0x84, 0x81, 0x52, 0xfd, 0x3c, 0x22, 0x89, 0xca, 0x50, 0xe1, 0xc3, 0xe5, 0x8c, 0x9a, 0x4f, 0xaa, 0xaf, 0xbd, 0xf5, 0x80, 0x3c, 0x54, 0x48, 0xdd, 0xb8, 0x45, 0x59, 0x7e, 0x8b, 0x01, 0x18, 0xe4, 0x3a, 0x81, 0xd3 };
        var reader1: std.Io.Reader = .fixed(&first_raw);
        const first = Block.parse(&reader1);
        try expect(first.bits == 0x18018b7e);
        // Block 473759
        const last_raw = [_]u8{ 0x02, 0x00, 0x00, 0x20, 0xf1, 0x47, 0x2d, 0x9d, 0xb4, 0xb5, 0x63, 0xc3, 0x5f, 0x97, 0xc4, 0x28, 0xac, 0x90, 0x3f, 0x23, 0xb7, 0xfc, 0x05, 0x5d, 0x1c, 0xfc, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb3, 0xf4, 0x49, 0xfc, 0xbe, 0x1b, 0xc4, 0xcf, 0xbc, 0xb8, 0x28, 0x3a, 0x0d, 0x2c, 0x03, 0x7f, 0x96, 0x1a, 0x3f, 0xdf, 0x2b, 0x8b, 0xed, 0xc1, 0x44, 0x97, 0x37, 0x35, 0xee, 0xa7, 0x07, 0xe1, 0x26, 0x42, 0x58, 0x59, 0x7e, 0x8b, 0x01, 0x18, 0xe5, 0xf0, 0x04, 0x74 };
        var reader2: std.Io.Reader = .fixed(&last_raw);
        const last = Block.parse(&reader2);
        try expect(last.bits == 0x18018b7e);
        const time_diff = last.timestamp - first.timestamp;
        const new_bits = Block.calculateNewBits(first.bits, time_diff);
        try expect(new_bits == 0x18018d30);
    }
    {
        // Block 0
        const first = @import("blockchain.zig").genesis_block;
        // Block 2015
        const last_raw = [_]u8{0x01, 0x00, 0x00, 0x00, 0xe2, 0x55, 0x09, 0xcd, 0xe7, 0x07, 0xc3, 0xd0, 0x2a, 0x69, 0x3e, 0x4f, 0xe9, 0xe7, 0xcd, 0xd5, 0x7c, 0x38, 0xa0, 0xd2, 0xc8, 0xd6, 0x34, 0x1f, 0x20, 0xda, 0xe8, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x3d, 0xf1, 0x18, 0x5e, 0x16, 0x2e, 0xe9, 0x2d, 0x03, 0x1f, 0xe2, 0x1d, 0x14, 0x00, 0xff, 0x7d, 0x70, 0x5a, 0x3e, 0x9b, 0x9c, 0x86, 0x0e, 0xea, 0x85, 0x53, 0x13, 0xcd, 0x8c, 0xa2, 0x6c, 0x08, 0x7f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x30, 0xb7, 0x32, 0x31};
        var reader: std.Io.Reader = .fixed(&last_raw);
        const last = Block.parse(&reader);
        try expect(last.bits == 0x1d00ffff);
        const time_diff = last.timestamp - first.timestamp;
        const new_bits = Block.calculateNewBits(first.bits, time_diff);
        try expect(new_bits == 0x1d00ffff);
    }
    {
        const new_bits = Block.calculateNewBits(0x1701fa38, 1141466);
        try expect(new_bits == 0x1701ddb4);
    }
}
//#endregion
