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

pub const State = struct {
    latest_block_header: u256,
    block_headers: []Bitcoin.Block,
    block_headers_count: u32,

    pub fn init(alloc: std.mem.Allocator) !State {
        var self: State = .{
            .latest_block_header = 0,
            .block_headers = try alloc.alloc(Bitcoin.Block, 1_000_000),
            .block_headers_count = 0,
        };

        self.latest_block_header = genesis_block_hash;
        self.block_headers[0] = genesis_block;
        self.block_headers_count = 1;

        return self;
    }

    pub fn deinit(self: State, alloc: std.mem.Allocator) void {
        alloc.free(self.block_headers);
    }

    // @TODO expect a specific difficulty
    pub fn append(self: *State, blocks: []Bitcoin.Block) !void {
        if (self.block_headers_count + blocks.len > self.block_headers.len)
            return error.BlockBufferFull;

        var prev_hash: [32]u8 = undefined;
        std.mem.writeInt(u256, &prev_hash, self.latest_block_header, .big);
        for (blocks) |block| {
            var hash: [32]u8 = undefined;
            block.hash(&hash);
            const pow = block.checkProofOfWork();
            const successive = std.mem.eql(u8, &block.prev_block, &prev_hash);
            //std.log.debug("[{d:0>7}] {s}: PoW {s}, prev {s}", .{
            //    self.block_headers_count + i,
            //    std.fmt.fmtSliceHexLower(hash[0..10]),
            //    if (pow) "OK" else "XX",
            //    if (successive) "OK" else "XX",
            //});
            if (!pow) return error.ProofOfWorkFailed;
            if (!successive) return error.NonSuccessiveBlocks;
            prev_hash = hash;
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
};
