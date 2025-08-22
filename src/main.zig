const std = @import("std");
const Thread = std.Thread;
const GenericWriter = std.io.GenericWriter;
const GenericReader = std.io.GenericReader;
const builtin = @import("builtin");

const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");
const Blockchain = @import("blockchain.zig");
const Address = std.net.Address;

pub const std_options = std.Options{
    .log_level = .info,
};

const app_name = "ZiglyNode";
const blockheaders_filename = "blockheaders.dat";
const max_connections = 8;
/// This value might change
const max_concurrent_tasks = max_connections;
const connection_timeout_seconds = 5;
comptime {
    // logic for `i 2` depends on that
    std.debug.assert(max_connections < 10);
}

const State = struct {
    privkey: u256,
    address: []u8,
    connections: [max_connections]struct { alive: bool, data: Network.Node.Connection },
    active_connections: u32,
    chain: Blockchain.State,
    /// Use this before writing to state in a multi-threaded context
    mutex: Thread.Mutex,
};

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
            @breakpoint(); // not sure what to do
            std.debug.print("Memory leak detected!\n", .{});
        }
    };

    var state_ptr: *State = try allocator.create(State);
    defer allocator.destroy(state_ptr);

    state_ptr.active_connections = 0;
    state_ptr.privkey = try std.fmt.parseInt(u256, @embedFile(".privkey")[0..64], 16);
    state_ptr.address = addr: {
        var addr_buf: [40]u8 = undefined;
        const address = Bitcoin.Address.fromPrivkey(state_ptr.privkey, true, &addr_buf);
        break :addr try allocator.dupe(u8, address);
    };
    defer allocator.free(state_ptr.address);

    state_ptr.mutex = Thread.Mutex{};

    state_ptr.chain = try Blockchain.State.init(allocator);
    defer state_ptr.chain.deinit(allocator);

    read_blockheaders_from_disk: {
        const appdata_dir = try std.fs.getAppDataDir(allocator, app_name);
        defer allocator.free(appdata_dir);
        std.fs.makeDirAbsolute(appdata_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const blockheaders_file_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ appdata_dir, std.fs.path.sep, blockheaders_filename });
        defer allocator.free(blockheaders_file_path);

        const blockheaders_file = std.fs.openFileAbsolute(blockheaders_file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.err("could not find existing {s}", .{blockheaders_file_path});
                break :read_blockheaders_from_disk;
            },
            else => break :read_blockheaders_from_disk,
        };
        defer blockheaders_file.close();
        std.log.info("loading block headers from {s}", .{blockheaders_file_path});

        const blockheaders_file_size = (try blockheaders_file.stat()).size;
        const bockheaders_file_valid = blockheaders_file_size != 0 and blockheaders_file_size % @sizeOf(Bitcoin.Block) == 0;

        if (!bockheaders_file_valid) {
            std.log.err("The file {s} is corrupt... fix or delete it before proceeding", .{blockheaders_file_path});
            break :read_blockheaders_from_disk;
        }

        const blockheaders_count = blockheaders_file_size / @sizeOf(Bitcoin.Block);
        for (state_ptr.chain.block_headers[1..][0..blockheaders_count], 0..) |*block, i| {
            var block_buffer: [@sizeOf(Bitcoin.Block)]u8 = undefined;
            _ = blockheaders_file.read(&block_buffer) catch |err| {
                std.log.err("failed to read block {d} in {s}: {s}", .{ i, blockheaders_file_path, @errorName(err) });
                break :read_blockheaders_from_disk;
            };
            for (std.mem.asBytes(block), std.mem.asBytes(&block_buffer)) |*out, read|
                out.* = read;
        }
        state_ptr.chain.block_headers_count = @intCast(blockheaders_count + 1);
        state_ptr.chain.latest_block_header = blk: {
            var buf: [32]u8 = undefined;
            state_ptr.chain.block_headers[state_ptr.chain.block_headers_count - 1].hash(&buf);
            break :blk std.mem.readInt(u256, &buf, .big);
        };
    }

    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("\nYour address is {s}\n", .{state_ptr.address});
    while (true) {
        try stdout.print("\n################################################\n", .{});
        try stdout.print("\nHello dear hodler, tell me what can I do for you\n", .{});
        try stdout.print("1. List peers (interact)\n", .{});
        try stdout.print("2. Connect to a new peer\n", .{});
        try stdout.print("3. View blockchain state\n", .{});
        try stdout.print("4. Sign a transaction\n", .{});
        try stdout.print("5. Exit\n\n", .{});

        var buf: [9]u8 = undefined;
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        const b = input[0];
        outerswitch: switch (b) {
            '1' => {
                const anyConnection = for (state_ptr.connections) |conn| {
                    if (conn.alive) break true;
                } else false;
                if (!anyConnection) {
                    try stdout.print("\n<empty>\n", .{});
                } else {
                    try stdout.print("======== Peer list ========\n", .{});
                    for (state_ptr.connections, 0..) |conn, i| {
                        if (conn.alive)
                            try stdout.print("\n{d}: {any} | {s}\n", .{ i + 1, conn.data.peer_address, conn.data.user_agent });
                    }
                    try stdout.print("\n===========================\n", .{});
                    try stdout.print("\nType 'i' followed by a number to interact with a peer (ex.: 'i 2')\n", .{});
                }
            },
            '2' => {
                const new_peer_id = for (state_ptr.connections, 0..) |conn, i| {
                    if (!conn.alive) break i;
                } else {
                    try stdout.print("\nERROR: reached maximum number of peers\n", .{});
                    break;
                };

                const target_ip_address = try Prompt.promptIpAddress(.{ .default_value = "127.0.0.1" });

                state_ptr.connections[new_peer_id].data = Network.Node.connect(target_ip_address, app_name, allocator, connection_timeout_seconds) catch |err| {
                    std.log.err("Failed to connect to {}: {s}", .{ target_ip_address, @errorName(err) });
                    continue;
                };
                state_ptr.connections[new_peer_id].alive = true;
                state_ptr.active_connections += 1;
                try stdout.print("\nConnection established successfully with \nPeer ID: {d}\nIP: {any}\nUser Agent: {s}\n\n", .{
                    new_peer_id + 1,
                    state_ptr.connections[new_peer_id].data.peer_address,
                    state_ptr.connections[new_peer_id].data.user_agent,
                });
            },
            'i' => {
                std.debug.assert(max_connections < 10); // Based on this premise we assume 3 character input: 'i', ' ' and 'X' as single-digit number
                const trimmed = std.mem.trimRight(u8, input, &.{ ' ', '\r', '\n' });
                if (trimmed.len != 3 or trimmed[1] != ' ' or trimmed[2] < '1' or trimmed[2] > '9') {
                    try stdout.print("Not sure what you mean... try like 'i 1'\n", .{});
                    break :outerswitch;
                }

                const peer_id = (try std.fmt.charToDigit(trimmed[2], 10)) - 1;
                if (!state_ptr.connections[peer_id].alive)
                    try stdout.print("That's not a valid peer id\n", .{});

                const connection_ptr = &state_ptr.connections[peer_id].data;
                try stdout.print("\nWhat do you want to do?\n", .{});
                try stdout.print("1. disconnect from peer\n", .{});
                try stdout.print("2. ask for block headers\n", .{});
                try stdout.print("3. ask for new peers and connect \n", .{});
                const action = try stdin.readUntilDelimiter(&buf, '\n');
                switch (action[0]) {
                    '1' => {
                        state_ptr.connections[peer_id].alive = false;
                        state_ptr.active_connections -= 1;
                    },
                    '2' => {
                        requestBlocks(state_ptr, connection_ptr, allocator) catch |err| {
                            try stdout.print("Could not request blocks: {s}", .{@errorName(err)});
                        };
                    },
                    '3' => {
                        var buffer: [max_concurrent_tasks * 105]u8 = undefined; // 105 is empirical and might change
                        var buffer_alloc = std.heap.FixedBufferAllocator.init(&buffer);
                        var pool: Thread.Pool = undefined;
                        try pool.init(.{ .allocator = buffer_alloc.allocator() }); // no deinit cause we're using a stack buffer
                        try requestNewPeers(state_ptr, connection_ptr, allocator, &pool);
                        while (pool.run_queue.popFirst() != null) {}
                        for (pool.threads) |thr| thr.detach();
                    },
                    else => continue,
                }
            },
            '3' => {
                try stdout.print("\n=== Blockchain State ===\n", .{});
                try stdout.print("Block headers count: {d}\n", .{state_ptr.chain.block_headers_count});

                if (state_ptr.chain.block_headers_count > 1)
                    try stdout.print("Latest block hash: {x:0>64}\n", .{state_ptr.chain.latest_block_header});
                try stdout.print("========================\n", .{});
            },
            '4' => {
                var tx = try promptTransaction(allocator);
                defer tx.deinit(allocator);
                const input_index = 0;
                var prompt_buf: [256]u8 = undefined;
                const prev_pubkey = try Prompt.promptBytesHex(&prompt_buf, "Previous pubkey");
                try tx.sign(state_ptr.privkey, input_index, prev_pubkey, allocator);
                const bytes = try tx.serialize(allocator);
                defer allocator.free(bytes);
                try stdout.print("\nTransaction:\n{}\n", .{std.fmt.fmtSliceHexLower(bytes)});
            },
            '5' => break,
            0x0d => return, // EndOfFile
            else => {
                try stdout.print("\ninvalid byte read: {x}\n", .{b});
            },
        }
    }

    std.log.info("saving data on disk...", .{});

    save_blockheaders_to_disk: {
        const appdata_dir = try std.fs.getAppDataDir(allocator, app_name);
        defer allocator.free(appdata_dir);
        std.fs.makeDirAbsolute(appdata_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const blockheaders_file_path = try std.fmt.allocPrint(allocator, "{s}{c}{s}", .{ appdata_dir, std.fs.path.sep, blockheaders_filename });
        defer allocator.free(blockheaders_file_path);

        const blockheaders_file = std.fs.createFileAbsolute(blockheaders_file_path, .{}) catch |err| {
            std.log.err("could not create {s}: {s}", .{ blockheaders_filename, @errorName(err) });
            break :save_blockheaders_to_disk;
        };
        defer blockheaders_file.close();

        // Save blocks excluding genesis block (starting from index 1)
        if (state_ptr.chain.block_headers_count > 1) {
            for (state_ptr.chain.block_headers[1..state_ptr.chain.block_headers_count]) |block| {
                const block_bytes = std.mem.asBytes(&block);
                _ = blockheaders_file.write(block_bytes) catch |err| {
                    std.log.err("failed to write block to {s}: {s}", .{ blockheaders_file_path, @errorName(err) });
                    break :save_blockheaders_to_disk;
                };
            }
        }
    }
}

fn promptTransaction(alloc: std.mem.Allocator) !Bitcoin.Tx {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("NOTE: Only P2PKH is currently supported\n", .{});
    const testnet = try Prompt.promptBool("Do you want to use testnet?");
    var buf: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;
    const prev_txid_bytes = try Prompt.promptBytesHex(&buf, "Previous TXID (32 bytes)");
    const prev_txid = try std.fmt.parseInt(u256, prev_txid_bytes[0..64], 16);
    const prev_output_index = try Prompt.promptInt(u32, "Previous output index", .{});
    const amount = try Prompt.promptInt(u64, "Amount to send", .{});
    const target_address = try Prompt.promptString(&buf2, "Target address", .{});
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
    fn promptBool(msg: []const u8) !bool {
        const stdout = std.io.getStdOut().writer();
        const stdin = std.io.getStdIn().reader();
        try stdout.print("{s} [y/n]: ", .{msg});
        var buf: [9]u8 = undefined;
        const input = try stdin.readUntilDelimiter(&buf, '\n');
        switch (input[0]) {
            'y' => return true,
            'n' => return false,
            else => return error.InvalidInput,
        }
    }

    fn promptBytesHex(buffer: []u8, msg: []const u8) ![]u8 {
        const stdout = std.io.getStdOut().writer();
        const stdin = std.io.getStdIn().reader();
        try stdout.print("{s} [hex]: ", .{msg});
        var answer = try stdin.readUntilDelimiter(buffer, '\n');
        if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
        return answer;
    }

    const PromptStringOpts = struct { default_value: ?[]const u8 = null };
    fn promptString(buffer: []u8, msg: []const u8, opt: PromptStringOpts) ![]u8 {
        const stdout = std.io.getStdOut().writer();
        const stdin = std.io.getStdIn().reader();

        var buf: [100]u8 = undefined;
        var default_indicator: []u8 = &[0]u8{};
        if (opt.default_value) |default|
            default_indicator = try std.fmt.bufPrint(&buf, " [default={s}]", .{default});

        try stdout.print("{s}{s}: ", .{ msg, default_indicator });
        var answer = try stdin.readUntilDelimiter(buffer, '\n');
        if (answer[answer.len - 1] == '\r') answer = answer[0 .. answer.len - 1];
        if (answer.len == 0 and opt.default_value != null) {
            for (opt.default_value.?, 0..) |ch, i| buffer[i] = ch;
            return buffer[0..opt.default_value.?.len];
        }

        return answer;
    }

    const PromptIntOpts = struct { default_value: ?comptime_int = null };
    fn promptInt(comptime T: type, msg: []const u8, opts: PromptIntOpts) !T {
        const stdout = std.io.getStdOut().writer();
        const stdin = std.io.getStdIn().reader();
        if (opts.default_value) |default| {
            try stdout.print("{s} [numeric, default={}]: ", .{ msg, default });
        } else {
            try stdout.print("{s} [numeric]: ", .{msg});
        }
        var buf: [256]u8 = undefined;
        var answer: []u8 = while (true) {
            const input = try stdin.readUntilDelimiter(&buf, '\n');
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
    fn promptIpAddress(opt: PromptIpOpts) !Address {
        var buf: [256]u8 = undefined;
        const ip = try promptString(&buf, "Enter the IPv4 or IPv6 [without port]", .{ .default_value = opt.default_value });
        const port = try promptInt(u16, "Enter the port", .{ .default_value = 8333 });
        return try Address.resolveIp(ip, port);
    }
};

fn requestBlocks(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Requesting for block headers...\n", .{});
    try Network.Node.sendMessage(connection, Network.Protocol.Message{
        .getheaders = .{
            .hash_count = 1,
            .hash_start_block = state.chain.latest_block_header,
            //.hash_final_block = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048, // genesis successor
            //.hash_final_block = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd, // genesis successor's successor
            .hash_final_block = 0,
        },
    });

    const message = try Network.Node.readUntilMessage(connection, Network.Protocol.Message.headers, alloc);
    defer message.deinit(alloc);
    std.debug.assert(message == .headers);
    const blocks = message.headers.data;
    try stdout.print("{d} new blocks received!\n", .{blocks.len});
    {
        state.mutex.lock();
        defer state.mutex.unlock();
        try state.chain.append(blocks);
    }
}

const ConnectWorkerParams = struct {
    state: *State,
    addr: *const Network.Protocol.Addr,
    new_connections_count: *u32,
    semaphore: *Thread.Semaphore,
    alloc: std.mem.Allocator,
};

fn requestNewPeers(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator, pool: *std.Thread.Pool) !void {
    if (state.active_connections >= max_connections) {
        std.log.err("Maximum number of connections reached: {}\n", .{max_connections});
        return error.MaximumNumberOfConnectionsReached;
    }
    std.log.info("Requesting for new peers and connecting...", .{});
    try Network.Node.sendMessage(connection, Network.Protocol.Message{ .getaddr = .{} });
    const message = try Network.Node.readUntilMessage(connection, Network.Protocol.Message.addr, alloc);
    defer message.deinit(alloc);
    std.debug.assert(message == .addr);
    std.log.debug("Received {} new addresses, trying to connect...", .{message.addr.count});

    var addr_ptr_array = try alloc.alloc(*Network.Protocol.Addr, message.addr.addr_array.len);
    defer alloc.free(addr_ptr_array);
    for (message.addr.addr_array, 0..) |*addr, i|
        addr_ptr_array[i] = addr;
    std.sort.heap(
        *Network.Protocol.Addr,
        addr_ptr_array,
        {},
        struct {
            pub fn desc(_: void, lhs: *Network.Protocol.Addr, rhs: *Network.Protocol.Addr) bool {
                return lhs.time > rhs.time;
            }
        }.desc,
    );
    var new_connections_count: u32 = 0;
    const num_tasks = @min(addr_ptr_array.len, max_concurrent_tasks);
    var semaphore = Thread.Semaphore{ .permits = num_tasks };
    for (addr_ptr_array[0..num_tasks]) |addr| {
        if (state.active_connections >= max_connections) break;
        try pool.spawn(
            struct {
                fn inner(worker_params: ConnectWorkerParams) void {
                    worker_params.semaphore.wait();
                    defer worker_params.semaphore.post();
                    const address = blk: {
                        if (std.mem.eql(u8, worker_params.addr.ip[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                            break :blk Address.initIp4(worker_params.addr.ip[12..].*, worker_params.addr.port);
                        } else {
                            break :blk Address.initIp6(worker_params.addr.ip, worker_params.addr.port, 0, 0);
                        }
                    };
                    std.log.info("Connecting to {}...", .{address});
                    const new_connection = Network.Node.connect(address, app_name, worker_params.alloc, connection_timeout_seconds) catch |err| {
                        // In the future we'll do something like this to immediatly dequeue next address
                        // worker_params.state.mutex.lock();
                        // defer worker_params.state.mutex.unlock();
                        // worker_params.pool.spawn
                        std.log.info("Connection to {} failed: {s}", .{ address, @errorName(err) });
                        return;
                    };
                    const connection_slot_ptr = for (&worker_params.state.connections) |*conn| {
                        if (!conn.alive) break conn;
                    } else {
                        std.log.info("Connection to {} completed but abandoned for lack of slots", .{address});
                        return;
                    };

                    {
                        worker_params.state.mutex.lock();
                        defer worker_params.state.mutex.unlock();
                        if (worker_params.state.active_connections >= max_connections) {
                            std.log.info("Connection to {} completed but abandoned because slots were filled while we waited for mutex lock", .{address});
                            //worker_params.event.set();
                            return;
                        }
                        connection_slot_ptr.*.data = new_connection;
                        connection_slot_ptr.*.alive = true;
                        worker_params.state.active_connections += 1;
                        worker_params.new_connections_count.* += 1;
                    }
                    std.log.info("Connected to {}", .{address});
                }
            }.inner,
            .{ConnectWorkerParams{ .state = state, .addr = addr, .new_connections_count = &new_connections_count, .semaphore = &semaphore, .alloc = alloc }},
        );
    }

    Thread.sleep(500_000_000);
    for (0..num_tasks) |_| semaphore.wait();

    std.log.info("Connected to {} new peers\n", .{new_connections_count});
}
