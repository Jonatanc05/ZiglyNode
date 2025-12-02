const Blockchain = @This();
const std = @import("std");
const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");

pub const genesis_block_hash: u256 = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

pub const genesis_block = Bitcoin.Block{
    .version = 0x00000001,
    .prev_block = [1]u8{0} ** 32,
    .merkle_root = [32]u8{ 0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b, 0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a, 0xfd, 0xed, 0xa3, 0x3b },
    .timestamp = 0x495fab29,
    .bits = 0x1d00ffff,
    .nonce = 0x1dac2b7c,
};

// Period of time, measured in blocks, in which we calculate PoW difficulty again
pub const difficulty_adjustment_period = 2016;

pub const State = struct {
    latest_block_header: u256,
    // TODO deal with invalid accesses (accessing undefined)
    /// First entry should always be genesis block
    block_headers: []Bitcoin.Block,
    /// Includes genesis block on the count
    block_headers_count: u32,
    /// We currently only support validating sequentially
    blocks_already_verified: u32,

    pub fn init(alloc: std.mem.Allocator) !State {
        var self: State = .{
            .block_headers = try alloc.alloc(Bitcoin.Block, 1_000_000),
            .block_headers_count = undefined,
            .latest_block_header = undefined,
            .blocks_already_verified = undefined,
        };

        self.block_headers[0] = genesis_block;
        self.block_headers_count = 1;
        self.latest_block_header = genesis_block_hash;
        self.blocks_already_verified = 0;

        return self;
    }

    pub fn deinit(self: State, alloc: std.mem.Allocator) void {
        alloc.free(self.block_headers);
    }

    /// refers to difficulty adjustment period
    pub fn firstBlockOfCurrentPeriod(self: State) *Bitcoin.Block {
        return &self.block_headers[
            self.block_headers_count - @rem(self.block_headers_count, difficulty_adjustment_period)
        ];
    }

    /// Not thread-safe
    pub fn append(self: *State, blocks: []Bitcoin.Block) !void {
        if (self.block_headers_count + blocks.len > self.block_headers.len)
            return error.BlockBufferFull;

        var prev_block_ptr: *Bitcoin.Block = &self.block_headers[self.block_headers_count - 1];
        var first_of_period = self.firstBlockOfCurrentPeriod();
        for (blocks, 0..) |*block_ptr, i| {
            const expected_pow_target_bits = bits: {
                const block_index: u32 = self.block_headers_count + @as(u32, @intCast(i));
                if (block_index % difficulty_adjustment_period == 0) {
                    const time_diff = prev_block_ptr.timestamp - first_of_period.timestamp;
                    first_of_period = block_ptr;
                    break :bits Bitcoin.Block.calculateNewBits(prev_block_ptr.bits, time_diff);
                } else break :bits prev_block_ptr.bits;
            };
            if (block_ptr.bits != expected_pow_target_bits)
                return error.UnexpectedProofOfWorkBits;

            if (!block_ptr.checkProofOfWork()) return error.ProofOfWorkFailed;
            var hash_buf: [32]u8 = undefined;
            prev_block_ptr.hash(&hash_buf);
            try std.testing.expectEqualSlices(u8, &block_ptr.prev_block, &hash_buf);
            if (!std.mem.eql(u8, &block_ptr.prev_block, &hash_buf)) return error.NonSuccessiveBlocks;
            prev_block_ptr = block_ptr;
        }

        std.mem.copyForwards(
            Bitcoin.Block,
            self.block_headers[self.block_headers_count..][0..blocks.len],
            blocks,
        );

        self.block_headers_count += @intCast(blocks.len);
        var buf: [32]u8 = undefined;
        self.block_headers[self.block_headers_count - 1].hash(&buf);
        self.latest_block_header = std.mem.readInt(u256, &buf, .big);
    }

    pub fn serialize(self: *State, writer: *std.Io.Writer) !void {
        try writer.writeInt(u32, self.block_headers_count, .little);
        // TODO I think this flush is residual from a debugging session. Try removing
        try writer.flush();

        // Save blocks excluding genesis block (which has index 0)
        if (self.block_headers_count > 1) {
            for (self.block_headers[1..self.block_headers_count]) |block| {
                try block.serialize(writer);
            }
        }
        try writer.flush();
    }

    pub fn parse(self: *State, reader: *std.Io.Reader) !void {
        self.block_headers_count = try reader.takeInt(u32, .little);

        self.block_headers[0] = genesis_block;
        for (self.block_headers[1..self.block_headers_count]) |*block| {
            block.* = Bitcoin.Block.parse(reader);
        }

        self.latest_block_header = blk: {
            var buf: [32]u8 = undefined;
            self.block_headers[self.block_headers_count - 1].hash(&buf);
            break :blk std.mem.readInt(u256, &buf, .big);
        };
    }
};

test "Genesis block" {
    const block_raw = [_]u8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x1d, 0xac, 0x2b, 0x7c };
    var reader: std.Io.Reader = .fixed(&block_raw);
    const block = Bitcoin.Block.parse(&reader);
    try std.testing.expectEqualDeep(block, genesis_block);
}

