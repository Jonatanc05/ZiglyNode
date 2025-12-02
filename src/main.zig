const std = @import("std");
const Thread = std.Thread;
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

    var state_ptr: *State = try allocator.create(State);
    defer allocator.destroy(state_ptr);

    state_ptr.active_connections = 0;
    state_ptr.privkey = privkey: {
        // Maybe use openAppFile later
        const filename = ".privkey";
        var resulting_file: std.fs.File = std.fs.cwd().openFile(filename, .{}) catch |err| switch (err) {
            error.FileNotFound => blk: {
                std.log.info("couldn't find {s} file, creating...", .{filename});
                const file = try std.fs.cwd().createFile(filename, .{ .read = true });
                try file.writeAll("0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a");
                try file.sync();
                try file.seekTo(0);
                break :blk file;
            },
            else => unreachable,
        };
        defer resulting_file.close();
        var buf: [64]u8 = undefined;
        const num_bytes_read = try resulting_file.readAll(&buf);
        std.debug.assert(num_bytes_read == 64);
        break :privkey try std.fmt.parseInt(u256, &buf, 16);
    };
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
        const blockheaders_file = openAppFile(allocator, blockheaders_filename, false) catch |err| switch(err) {
            error.FileNotFound => {
                std.log.warn("could not find existing {s}", .{blockheaders_filename});
                break :read_blockheaders_from_disk;
            },
            else => break :read_blockheaders_from_disk,
        };
        defer blockheaders_file.close();

        var buf: [@sizeOf(Bitcoin.Block)]u8 = undefined;
        var reader = blockheaders_file.reader(&buf);
        state_ptr.chain.parse(&reader.interface) catch {
            std.log.err("The {s} file is corrupt (or from previous ZiglyNode versions)... fix or delete it before proceeding", .{blockheaders_filename});
            return error.BlockheadersFileCorrupt;
        };
    }

    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buffer);
    const stdin = &stdin_reader.interface;

    try stdout.print("\nYour address is {s}\n", .{state_ptr.address});
    while (true) {
        try stdout.print("\n################################################\n", .{});
        try stdout.print("#                                              #\n", .{});
        try stdout.print("# Hello dear hodler, tell me what to do        #\n", .{});
        try stdout.print("#   1. View blockchain state                   #\n", .{});
        try stdout.print("#   2. Connect to a new peer                   #\n", .{});
        try stdout.print("#   3. List peers ({d})                          #\n",
            .{ active_connections_count: {
                var count: u32 = 0;
                for (state_ptr.connections) |c| {
                    count += if (c.alive) 1 else 0;
                }
                break :active_connections_count count;
            }
        });
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
                const new_peer_id = for (state_ptr.connections, 0..) |conn, i| {
                    if (!conn.alive) break i;
                } else {
                    try stdout.print("\nERROR: reached maximum number of peers\n", .{});
                    break;
                };

                const target_ip_address = try Prompt.promptIpAddress(stdout, stdin, .{ .default_value = "127.0.0.1" });
                try prepareOutput(stdout);

                state_ptr.connections[new_peer_id].data = Network.Node.connect(target_ip_address, app_name, allocator, connection_timeout_seconds) catch |err| {
                    std.log.err("Failed to connect to {f}: {t}", .{ target_ip_address, err });
                    continue;
                };
                state_ptr.connections[new_peer_id].alive = true;
                state_ptr.active_connections += 1;
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
                        try stdout.print("\n{d}: {f} | {s}\n", .{ i + 1, conn.data.peer_address, conn.data.user_agent });
                }
                try stdout.print("\n===========================\n", .{});
                try stdout.print("\nType 'i' followed by a number to interact with a peer (ex.: 'i 2')\n", .{});
            },
            '4' => {
                var tx = try promptTransaction(allocator, stdout, stdin);
                defer tx.deinit(allocator);
                const input_index = 0;
                const prev_pubkey = try Prompt.promptBytesHex("Previous pubkey script (25 bytes for P2PKH)", stdout, stdin);
                try tx.sign(state_ptr.privkey, input_index, prev_pubkey, allocator);

                var growing_buffer = try std.ArrayList(u8).initCapacity(allocator, 100);
                var writer_concrete: std.Io.Writer.Allocating = .fromArrayList(allocator, &growing_buffer);
                defer writer_concrete.deinit();

                tx.serialize(&writer_concrete.writer) catch return error.OutOfMemory;
                const bytes = try writer_concrete.toOwnedSlice();
                defer allocator.free(bytes);
                try stdout.print("\nSigned transaction:\n{x}\n", .{bytes});
                try stdout.print("\nYou can verifiy the transaction contents using the command `bitcoin tx -json <hex>`\n", .{});
            },
            '5' => break,
            'i' => {
                std.debug.assert(max_connections < 10); // Based on this premise we assume 3 character input: 'i', ' ' and 'X' as single-digit number
                const trimmed = std.mem.trimRight(u8, input, &.{ ' ', '\r', '\n' });
                if (trimmed.len != 3 or trimmed[1] != ' ' or trimmed[2] < '1' or trimmed[2] > '9') {
                    try stdout.print("Not sure what you mean... try like 'i 1'\n", .{});
                    break :outerswitch;
                }

                const peer_id = (try std.fmt.charToDigit(trimmed[2], 10)) - 1;
                if (!state_ptr.connections[peer_id].alive) {
                    try stdout.print("That's not a valid peer id\n", .{});
                    break :outerswitch;
                }

                const connection_ptr = &state_ptr.connections[peer_id].data;
                try stdout.print("\nWhat do you want to do?\n", .{});
                try stdout.print("1. disconnect from peer\n", .{});
                try stdout.print("2. ask for new peers and connect \n", .{});
                try stdout.print("3. ask for block headers\n", .{});
                try stdout.print("4. ask for many block headers\n", .{});
                try stdout.print("5. ask for entire blocks\n", .{});
                const action = try stdin.takeDelimiterExclusive('\n');
                std.debug.assert(try stdin.discardShort(1) == 1);
                switch (action[0]) {
                    '1' => {
                        state_ptr.connections[peer_id].alive = false;
                        state_ptr.active_connections -= 1;
                    },
                    '2' => {
                        var buffer: [max_concurrent_tasks * 105]u8 = undefined; // 105 is empirical and might change
                        var buffer_alloc = std.heap.FixedBufferAllocator.init(&buffer);
                        var pool: Thread.Pool = undefined;
                        try pool.init(.{ .allocator = buffer_alloc.allocator() }); // no deinit cause we're using a stack buffer
                        requestNewPeers(state_ptr, connection_ptr, allocator, &pool) catch {
                            try stdout.print("Could not complete address list request to {f}\n", .{ connection_ptr.peer_address });
                        };
                        while (pool.run_queue.popFirst() != null) {}
                        for (pool.threads) |thr| thr.detach();
                    },
                    '3' => {
                        const result = requestBlocks(state_ptr, connection_ptr, allocator, stdout);
                        if (result) |block_count| {
                            try stdout.print("{d} new blocks received!\n", .{block_count});
                        } else |err| {
                            try stdout.print("Could not request blocks: {t}", .{err});
                        }
                    },
                    '4' => {
                        var requests_count = try Prompt.promptInt(u32, "Type how many requests for new headers to make (2000 blocks/request)", stdout, stdin, .{});
                        requests: while (requests_count > 0) : (requests_count -= 1) {
                            const result = requestBlocks(state_ptr, connection_ptr, allocator, stdout);
                            try prepareOutput(stdout);
                            if (result) |block_count| {
                                try stdout.print("Total blocks: {d:0>7}\n", .{state_ptr.chain.block_headers_count});
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
                    '5' => {
                        try Network.Node.sendMessage(connection_ptr,
                            Network.Protocol.Message{
                                .getdata = payload_with_hashes_of_blocks_being_requested: {
                                    if (state_ptr.chain.block_headers_count <= state_ptr.chain.blocks_already_verified) {
                                        try prepareOutput(stdout);
                                        try stdout.print("We have verified all the blocks we're aware of. Maybe try asking for new block headers?\n", .{});
                                        continue;
                                    }
                                    const amount_to_verify = state_ptr.chain.block_headers_count - state_ptr.chain.blocks_already_verified;
                                    const amount_to_request_now = @min(amount_to_verify, 1); // TODO Adjust max limit
                                    var result = Network.Protocol.Message.ObjectDescriptionsMessage("getdata") {
                                        .count = amount_to_request_now,
                                        .inventory = try allocator.alloc(Network.Protocol.ObjectDescription, amount_to_request_now),
                                    };

                                    for ((&result).inventory, state_ptr.chain.blocks_already_verified..) |*inv_item, idx| {
                                        inv_item.@"type" = Network.Protocol.ObjectType.MSG_BLOCK;
                                        var buf: [32]u8 = undefined;
                                        // TODO cache theses hashes?
                                        state_ptr.chain.block_headers[idx].hash(&buf);
                                        inv_item.hash = std.mem.readInt(u256, &buf, .big);
                                    }
                                    break :payload_with_hashes_of_blocks_being_requested result;
                                },
                            }
                        );
                        const msg = try Network.Node.readUntilAnyOfGivenMessageTags(connection_ptr, &.{Network.Protocol.Message.block, Network.Protocol.Message.notfound}, allocator);
                        std.debug.print("block msg: {any}\n", .{msg});
                    },
                    else => continue,
                }
            },
            0x0d => return, // EndOfFile
            else => {
                try stdout.print("\ninvalid byte read: {x}\n", .{b});
            },
        }
    }

    std.log.info("saving data on disk...", .{});

    write_blockheaders_to_disk: {
        const blockheaders_file = openAppFile(allocator, blockheaders_filename, true) catch |err| {
            std.log.err("could not create {s}: {t}", .{ blockheaders_filename, err });
            break :write_blockheaders_to_disk;
        };
        defer blockheaders_file.close();

        var buf: [@sizeOf(Bitcoin.Block)]u8 = undefined;
        var writer = blockheaders_file.writer(&buf);
        state_ptr.chain.serialize(&writer.interface) catch |err| {
            std.log.err("failed to write blocks to {s}: {t}", .{ blockheaders_filename, err });
            break :write_blockheaders_to_disk;
        };
    }
}

fn prepareOutput(stdout: ?*std.Io.Writer) !void {
    if (stdout) |out| {
        try out.print("\n\n\n\n\n\n\n\n\n\n", .{});
    } else {
        var stdout_writer = std.fs.File.stdout().writer(&.{});
        const out = &stdout_writer.interface;
        try out.print("\n\n\n\n\n\n\n\n\n\n", .{});
    }
}

fn promptTransaction(alloc: std.mem.Allocator, out: *std.Io.Writer, in: *std.Io.Reader) !Bitcoin.Tx {
    try out.print("NOTE: Only P2PKH is currently supported\n", .{});
    const testnet = try Prompt.promptBool("Do you want to use testnet?", out, in);
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

fn requestBlocks(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator, out: *std.Io.Writer) !usize {
    try out.print("Requesting for block headers...\n", .{});
    try Network.Node.sendMessage(connection, Network.Protocol.Message{
        .getheaders = .{
            .hash_count = 1,
            .hash_start_block = state.chain.latest_block_header,
            //.hash_final_block = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048, // genesis successor
            //.hash_final_block = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd, // genesis successor's successor
            .hash_final_block = 0,
        },
    });

    const message = try Network.Node.readUntilAnyOfGivenMessageTags(connection, &.{Network.Protocol.Message.headers}, alloc);
    defer message.deinit(alloc);
    std.debug.assert(message == .headers);
    const blocks = message.headers.data;
    {
        state.mutex.lock();
        defer state.mutex.unlock();
        try state.chain.append(blocks);
    }
    return blocks.len;
}

const ConnectWorkerParams = struct {
    state: *State,
    addr: *const Network.Protocol.Addr,
    new_connections_count: *u32,
    semaphore: *Thread.Semaphore,
    alloc: std.mem.Allocator,
};

/// Blocks current thread
fn requestNewPeers(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator, pool: *std.Thread.Pool) !void {
    if (state.active_connections >= max_connections) {
        std.log.err("Maximum number of connections reached: {}\n", .{max_connections});
        return error.MaximumNumberOfConnectionsReached;
    }
    std.log.info("Requesting for new peers and connecting...", .{});
    try Network.Node.sendMessage(connection, Network.Protocol.Message{ .getaddr = .{} });
    const message = try Network.Node.readUntilAnyOfGivenMessageTags(connection, &.{Network.Protocol.Message.addr}, alloc);
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
                    std.log.info("Connecting to {f}...", .{address});
                    const new_connection = Network.Node.connect(address, app_name, worker_params.alloc, connection_timeout_seconds) catch |err| {
                        // In the future we'll do something like this to immediatly dequeue next address
                        // worker_params.state.mutex.lock();
                        // defer worker_params.state.mutex.unlock();
                        // worker_params.pool.spawn
                        std.log.info("Connection to {f} failed: {t}", .{ address, err });
                        return;
                    };
                    const connection_slot_ptr = for (&worker_params.state.connections) |*conn| {
                        if (!conn.alive) break conn;
                    } else {
                        std.log.info("Connection to {f} completed but abandoned for lack of slots", .{address});
                        return;
                    };

                    {
                        worker_params.state.mutex.lock();
                        defer worker_params.state.mutex.unlock();
                        if (worker_params.state.active_connections >= max_connections) {
                            std.log.info("Connection to {f} completed but abandoned because slots were filled while we waited for mutex lock", .{address});
                            //worker_params.event.set();
                            return;
                        }
                        connection_slot_ptr.*.data = new_connection;
                        connection_slot_ptr.*.alive = true;
                        worker_params.state.active_connections += 1;
                        worker_params.new_connections_count.* += 1;
                    }
                    std.log.info("Connected to {f}", .{address});
                }
            }.inner,
            .{ConnectWorkerParams{ .state = state, .addr = addr, .new_connections_count = &new_connections_count, .semaphore = &semaphore, .alloc = alloc }},
        );
    }

    Thread.sleep(500_000_000);
    for (0..num_tasks) |_| semaphore.wait();

    try prepareOutput(null);
    std.log.info("Connected to {d} new peers\n", .{new_connections_count});
}

const OpenAppFileError = std.fs.File.OpenError || std.fs.GetAppDataDirError;
/// Caller is reponsible for calling `.close()` on file returned
fn openAppFile(gpa: std.mem.Allocator, filename: []const u8, comptime override_existing: bool) OpenAppFileError!std.fs.File {
    const appdata_dir = try std.fs.getAppDataDir(gpa, app_name);
    defer gpa.free(appdata_dir);
    std.fs.makeDirAbsolute(appdata_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => std.debug.panicExtra(null, "Error calling std.fs.makeDirAbsolute(\"{s}\")", .{appdata_dir}),
    };

    const filepath = try std.fmt.allocPrint(gpa, "{s}{c}{s}", .{ appdata_dir, std.fs.path.sep, filename });
    defer gpa.free(filepath);

    std.log.info("accessing {s}...", .{filepath});
    if (override_existing) {
        return try std.fs.createFileAbsolute(filepath, .{});
    } else {
        return std.fs.openFileAbsolute(filepath, .{});
    }
}
