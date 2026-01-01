const std = @import("std");
const Thread = std.Thread;
const builtin = @import("builtin");

const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");
const Blockchain = @import("blockchain.zig");
const ZiglyNode = @import("ziglynode-core.zig");
const Address = std.net.Address;

comptime {
    // logic for `i 2` depends on that
    std.debug.assert(ZiglyNode.max_connections < 10);
}

pub const std_options = std.Options{
    .log_level = .info,
};

var stdout_buffer: [0]u8 = undefined;
var stdin_buffer: [1024]u8 = undefined;

pub fn main() !void {
    const allocator, var debug: ?std.heap.DebugAllocator(.{}) = blk: {
        if (builtin.mode == .Debug) {
            var gpa = std.heap.DebugAllocator(.{}).init;
            break :blk .{ gpa.allocator(), gpa };
        } else {
            break :blk .{ std.heap.smp_allocator, null };
        }
    };
    defer if (debug != null) {
        if (debug.?.deinit() == .leak) {
            @breakpoint();
            std.debug.print("Memory leak detected!\n", .{});
        }
    };

    var state_ptr: *ZiglyNode.State = try ZiglyNode.State.initAndLoad(allocator);
    defer state_ptr.deinit(allocator);

    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buffer);
    const stdin = &stdin_reader.interface;

    try prepareOutput(stdout);
    try stdout.print("\nYour address is {s}\n", .{state_ptr.address});
    while (true) {
        try stdout.print("\n################################################\n", .{});
        try stdout.print("#                                              #\n", .{});
        try stdout.print("# Hello dear hodler, tell me what to do        #\n", .{});
        try stdout.print("#   1. View blockchain state                   #\n", .{});
        try stdout.print("#   2. Connect to a new peer                   #\n", .{});
        try stdout.print("#   3. List peers ({d})                          #\n", .{state_ptr.active_connections});
        try stdout.print("#   4. Sign a transaction                      #\n", .{});
        try stdout.print("#   5. Exit                                    #\n", .{});
        try stdout.print("#                                              #\n", .{});
        try stdout.print("# NOTE: Type \"i <N>\" to interact with peer     #\n", .{});
        try stdout.print("# number N                                     #\n", .{});
        try stdout.print("################################################\n", .{});

        const input = try stdin.takeDelimiterExclusive('\n');
        std.debug.assert(try stdin.discardShort(1) == 1);
        if (input.len == 0) continue;
        const b = input[0];
        outerswitch: switch (b) {
            '1' => {
                try prepareOutput(stdout);
                try stdout.print("\n=== Blockchain State ===\n", .{});
                try stdout.print("Block headers count: {d}\n", .{state_ptr.chain.block_headers_count});

                if (state_ptr.chain.block_headers_count > 1)
                    try stdout.print("Latest block header: {x:0>64}\n", .{state_ptr.chain.latest_block_header});
                try stdout.print("========================\n", .{});
            },
            '2' => {
                const new_peer_id = state_ptr.idOfNextConnection() catch |err| switch (err) {
                    error.MaximumNumberOfConnectionsReached => {
                        std.log.err("Reached maximum number of peers, can't make new connections", .{});
                        break :outerswitch;
                    }
                };

                const target_ip_address = try Prompt.promptIpAddress(stdout, stdin, .{ .default_value = "127.0.0.1" });
                try prepareOutput(stdout);

                ZiglyNode.newConnection(state_ptr, allocator, target_ip_address) catch break :outerswitch;
                try stdout.print("\nConnection established successfully with \nPeer ID: {d}\nIP: {f}\nUser Agent: {s}\n\n", .{
                    new_peer_id + 1,
                    state_ptr.connections[new_peer_id].data.peer_address,
                    state_ptr.connections[new_peer_id].data.user_agent,
                });
            },
            '3' => {
                try prepareOutput(stdout);
                try stdout.print("======== Peer list ========\n", .{});
                for (state_ptr.connections, 0..) |conn, i| {
                    if (conn.alive)
                        try stdout.print("\n{d}: {f} | {s}{s}\n", .{
                            i + 1,
                            conn.data.peer_address,
                            std.mem.trimEnd(u8, &conn.data.user_agent, " "),
                            if (conn.data.isFullArchivalNode()) " | Full Archival" else "",
                        });
                }
                try stdout.print("\n===========================\n", .{});
                try stdout.print("\nType 'i' followed by a number to interact with a peer (ex.: 'i 2')\n", .{});
            },
            '4' => {
                var tx = try promptTransaction(allocator, stdout, stdin, Blockchain.isTestnet(state_ptr.chain.network));
                defer tx.deinit(allocator);
                const prev_pubkey = try Prompt.promptBytesHex("Previous pubkey script (25 bytes for P2PKH)", stdout, stdin);
                const input_index = 0;
                try tx.sign(state_ptr.privkey, input_index, prev_pubkey, allocator);

                const tx_bytes = blk: {
                    var growing_buffer = try std.ArrayList(u8).initCapacity(allocator, 100);
                    var writer_concrete: std.Io.Writer.Allocating = .fromArrayList(allocator, &growing_buffer);
                    defer writer_concrete.deinit();

                    tx.serialize(&writer_concrete.writer) catch return error.OutOfMemory;
                    break :blk try writer_concrete.toOwnedSlice();
                };
                defer allocator.free(tx_bytes);

                try stdout.print("\nSigned transaction:\n{x}\n", .{tx_bytes});
                try stdout.print("\nYou can verifiy the transaction contents using the command `bitcoin tx -json <hex>`\n", .{});
                // // TODO function Bitcoin.Tx.txid
                // if (state_ptr.active_connections > 0) {
                //     const advertise = try Prompt.promptBool("Advertise transaction to network?\n", stdout, stdin);
                //     if (advertise) {
                //         try ZiglyNode.advertiseTransaction(state_ptr, allocator, 0x00);
                //     }
                // } else {
                //     try stdout.print("No peers to advertise the transaction right now\n", .{});
                // }
            },
            '5' => break,
            'i' => {
                std.debug.assert(ZiglyNode.max_connections < 10); // Based on this premise we assume 3 character input: 'i', ' ' and 'X' as single-digit number
                const trimmed = std.mem.trimRight(u8, input, &.{ ' ', '\r', '\n' });
                if (trimmed.len != 3 or trimmed[1] != ' ' or trimmed[2] < '1' or trimmed[2] > '9') {
                    try prepareOutput(stdout);
                    try stdout.print("Not sure what you mean... try like 'i 1'\n", .{});
                    break :outerswitch;
                }

                const peer_id = (try std.fmt.charToDigit(trimmed[2], 10)) - 1;
                if (!state_ptr.connections[peer_id].alive) {
                    try prepareOutput(stdout);
                    try stdout.print("That's not a valid peer id\n", .{});
                    break :outerswitch;
                }

                const connection_ptr = &state_ptr.connections[peer_id].data;
                try stdout.print("\nWhat do you want to do?\n", .{});
                try stdout.print("1. disconnect from peer\n", .{});
                try stdout.print("2. ask for new peers and connect \n", .{});
                try stdout.print("3. ask for block headers\n", .{});
                try stdout.print("4. ask for entire blocks\n", .{});
                const action = try stdin.takeDelimiterExclusive('\n');
                std.debug.assert(try stdin.discardShort(1) == 1);
                switch (action[0]) {
                    '1' => {
                        state_ptr.connections[peer_id].alive = false;
                        state_ptr.active_connections -= 1;
                    },
                    '2' => {
                        try prepareOutput(stdout);

                        ZiglyNode.requestNewPeers(state_ptr, connection_ptr, allocator) catch {
                            std.log.err("Could not complete address list request to {f}", .{ connection_ptr.peer_address });
                        };
                    },
                    '3' => {
                        var requests_count = try Prompt.promptInt(u32, "How many requests to send (2000 blocks/request)", stdout, stdin, .{ .default_value = 1 });
                        try prepareOutput(stdout);
                        requests: while (requests_count > 0) : (requests_count -= 1) {
                            const result = ZiglyNode.requestBlocks(state_ptr, connection_ptr, allocator, stdout);
                            if (result) |block_count| {
                                try stdout.print("Blocks received. Total blocks: {d:0>7}\n", .{state_ptr.chain.block_headers_count});
                                if (block_count < 2000) {
                                    try stdout.print("Less than 2000 blocks received, assume end", .{}); // Obviously broken
                                    break :requests;
                                }
                            } else |err| {
                                try stdout.print("Could not request blocks: {t}", .{err});
                                break :requests;
                            }
                        }
                    },
                    '4' => {
                        try prepareOutput(stdout);
                        const block_msg = ZiglyNode.requestActualBlocks(state_ptr, allocator, connection_ptr) catch break :outerswitch;
                        defer block_msg.deinit(allocator);
                        try stdout.print("Block header: {any}\n", .{block_msg.block.header});
                    },
                    else => break :outerswitch,
                }
            },
            0x0d => return, // EndOfFile
            else => {
                try stdout.print("\ninvalid byte read: {x}\n", .{b});
            },
        }
    }

    state_ptr.writeBlockheadersToDisk(allocator);
}

fn prepareOutput(stdout: ?*std.Io.Writer) !void {
    const out_str = [_]u8{0x1b, '[', '2', 'J', 0x1b, '[', 'H'};
    // "\n\n\n\n\n\n\n\n\n\n"
    if (stdout) |out| {
        try out.print(&out_str, .{});
    } else {
        var stdout_writer = std.fs.File.stdout().writer(&.{});
        const out = &stdout_writer.interface;
        try out.print(&out_str, .{});
    }
}

fn promptTransaction(alloc: std.mem.Allocator, out: *std.Io.Writer, in: *std.Io.Reader, testnet: bool) !Bitcoin.Tx {
    try out.print("NOTE: Only P2PKH is currently supported\n", .{});
    const prev_txid_bytes = try Prompt.promptBytesHex("Previous TXID (32 bytes)", out, in);
    const prev_txid = try std.fmt.parseInt(u256, prev_txid_bytes[0..64], 16);
    const prev_output_index = try Prompt.promptInt(u32, "Previous output index", out, in, .{});
    const amount = try Prompt.promptInt(u64, "Amount to send (sats)", out, in, .{});
    const target_address = try Prompt.promptString("Target address", out, in, .{});
    return try Bitcoin.Tx.initP2PKH(.{
        .testnet = testnet,
        .prev_txid = prev_txid,
        .prev_output_index = prev_output_index,
        .amount = amount,
        .target_address = target_address,
        .alloc = alloc,
    });
}

const Prompt = struct {
    fn promptBool(msg: []const u8, out: *std.Io.Writer, in: *std.Io.Reader) !bool {
        try out.print("{s} [y/n]: ", .{msg});
        const input = try in.takeDelimiterExclusive('\n');
        std.debug.assert(try in.discardShort(1) == 1);
        switch (input[0]) {
            'y' => return true,
            'n' => return false,
            else => return error.InvalidInput,
        }
    }

    fn promptBytesHex(msg: []const u8, out: *std.Io.Writer, in: *std.Io.Reader) ![]u8 {
        try out.print("{s} [hex]: ", .{msg});
        var answer = try in.takeDelimiterExclusive('\n');
        std.debug.assert(try in.discardShort(1) == 1);
        if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
        return answer;
    }

    const PromptStringOpts = struct { default_value: ?[]const u8 = null };
    fn promptString(msg: []const u8, out: *std.Io.Writer, in: *std.Io.Reader, opt: PromptStringOpts) ![]const u8 {
        var buf: [100]u8 = undefined;
        var default_indicator: []u8 = &[0]u8{};
        if (opt.default_value) |default|
            default_indicator = try std.fmt.bufPrint(&buf, " [default={s}]", .{default});

        try out.print("{s}{s}: ", .{ msg, default_indicator });
        var answer = try in.takeDelimiterExclusive('\n');
        std.debug.assert(try in.discardShort(1) == 1);
        if (answer.len > 0 and answer[answer.len - 1] == '\r')
            answer = answer[0 .. answer.len - 1];

        if (answer.len == 0 and opt.default_value != null)
            return opt.default_value.?;
        return answer;
    }

    const PromptIntOpts = struct { default_value: ?comptime_int = null };
    fn promptInt(comptime T: type, msg: []const u8, out: *std.Io.Writer, in: *std.Io.Reader, opts: PromptIntOpts) !T {
        if (opts.default_value) |default| {
            try out.print("{s} [numeric, default={}]: ", .{ msg, default });
        } else {
            try out.print("{s} [numeric]: ", .{msg});
        }
        var answer: []u8 = while (true) {
            const input = try in.takeDelimiterExclusive('\n');
            std.debug.assert(try in.discardShort(1) == 1);
            if (input.len > 0 and input[0] != '\n' and input[0] != '\r') {
                break input;
            } else if (opts.default_value != null) {
                break &[0]u8{};
            }
        };
        if (answer.len == 0) return opts.default_value orelse unreachable;
        if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
        return try std.fmt.parseInt(T, answer[0..], 10);
    }

    const PromptIpOpts = struct { default_value: ?[]const u8 = null };
    fn promptIpAddress(out: *std.Io.Writer, in: *std.Io.Reader, opt: PromptIpOpts) !Address {
        const ip = try promptString("Enter the IPv4 or IPv6 [without port]", out, in, .{ .default_value = opt.default_value });
        var ip_copy: [40]u8 = undefined;
        for (ip, 0..) |_, i| ip_copy[i] = ip[i];
        const port = try promptInt(u16, "Enter the port", out, in, .{ .default_value = 8333 });
        return try Address.resolveIp(ip_copy[0..ip.len], port);
    }
};

