const std = @import("std");
const Thread = std.Thread;
const builtin = @import("builtin");

const Bitcoin = @import("bitcoin.zig");
const Network = @import("network.zig");
const Blockchain = @import("blockchain.zig");
const Address = std.net.Address;

pub const app_name = "ZiglyNode";
pub const max_connections = 8;

pub fn getBlockheadersFilename(state: *const State) []const u8 {
    switch (state.chain.network) {
        .mainnet => return blockheaders_filename_mainnet,
        .signet => return blockheaders_filename_signet,
    }
}

comptime {
    // logic for `i 2` depends on that
    std.debug.assert(max_connections < 10);
}
pub const blockheaders_filename_mainnet = "blockheaders.dat";
pub const blockheaders_filename_signet = "blockheaders_signet.dat";
pub const max_concurrent_tasks = max_connections;
/// This value might change
pub const connection_timeout_seconds = 5;

pub const State = struct {
    /// Use this before writing to state in a multi-threaded context
    mutex: Thread.Mutex,
    privkey: u256,
    address: []u8,
    connections: [max_connections]struct { alive: bool, data: Network.Node.Connection },
    active_connections: u32,
    chain: Blockchain.State,
    initial_block_header_count: u32,

    pub fn initAndLoad(allocator: std.mem.Allocator) !*State {
        var state_ptr: *State = try allocator.create(State);

        state_ptr.active_connections = 0;
        state_ptr.privkey = privkey: {
            const filename = ".privkey";
            var resulting_file = openAppFile(allocator, filename, .{}) catch |err| switch(err) {
                error.FileNotFound => blk: {
                    std.log.info("couldn't find {s} file, creating...", .{filename});
                    const filepath = try getAppFileAbsolutePath(allocator, filename);
                    const file = try std.fs.createFileAbsolute(filepath, .{ .read = true });
                    try file.writeAll("0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a");
                    try file.sync();
                    try file.seekTo(0);
                    break :blk file;
                },
                else => return err,
            };
            defer resulting_file.close();
            var buf: [64]u8 = undefined;
            const num_bytes_read = try resulting_file.readAll(&buf);
            std.debug.assert(num_bytes_read == 64);
            break :privkey try std.fmt.parseInt(u256, &buf, 16);
        };
        state_ptr.address = addr: {
            var addr_buf: [40]u8 = undefined;
            const address = Bitcoin.Address.fromPrivkey(state_ptr.privkey, Blockchain.isTestnet(state_ptr.chain.network), &addr_buf);
            break :addr try allocator.dupe(u8, address);
        };

        state_ptr.mutex = Thread.Mutex{};

        state_ptr.chain = try Blockchain.State.init(allocator);

        state_ptr.chain.network = blk: {
            const args = try std.process.argsAlloc(allocator);
            defer std.process.argsFree(allocator, args);
            for (args) |arg| {
                if (std.mem.eql(u8, arg, "--signet"))
                    break :blk .signet;
            }
            break :blk .mainnet;
        };

        const blockheaders_filename = getBlockheadersFilename(state_ptr);

        read_blockheaders_from_disk: {
            const blockheaders_file = openAppFile(allocator, blockheaders_filename, .{}) catch |err| switch(err) {
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
                std.log.err("The {s} file is corrupt (or from incompatible ZiglyNode versions)... fix or delete it before proceeding", .{blockheaders_filename});
                return error.BlockheadersFileCorrupt;
            };
        }

        state_ptr.initial_block_header_count = state_ptr.chain.block_headers_count;

        return state_ptr;
    }

    pub fn deinit(self: *const State, allocator: std.mem.Allocator) void {
        self.chain.deinit(allocator);
        allocator.free(self.address);
        allocator.destroy(self);
    }

    pub fn writeBlockheadersToDisk(self: *const State, allocator: std.mem.Allocator) void {
        if (self.chain.block_headers_count != self.initial_block_header_count) {
            std.log.info("saving data on disk...", .{});

            const blockheaders_filename = getBlockheadersFilename(self);

            write_blockheaders_to_disk: {
                const blockheaders_file = openAppFile(allocator, blockheaders_filename, .{.override_existing = true}) catch |err| {
                    std.log.err("could not create {s}: {t}", .{ blockheaders_filename, err });
                    break :write_blockheaders_to_disk;
                };
                defer blockheaders_file.close();

                var buf: [@sizeOf(Bitcoin.Block)]u8 = undefined;
                var writer = blockheaders_file.writer(&buf);
                self.chain.serialize(&writer.interface) catch |err| {
                    std.log.err("failed to write blocks to {s}: {t}", .{ blockheaders_filename, err });
                    break :write_blockheaders_to_disk;
                };
            }
        }
    }

    pub fn idOfNextConnection(self: *const State) error{MaximumNumberOfConnectionsReached}!usize {
        return for (self.connections, 0..) |conn, i| {
            if (!conn.alive) break i;
        } else return error.MaximumNumberOfConnectionsReached;
    }

};

pub fn newConnection(state_ptr: *State, allocator: std.mem.Allocator, target_ip_address: std.net.Address) !void {
    const new_peer_id = try state_ptr.idOfNextConnection();
    state_ptr.connections[new_peer_id].data = Network.Node.connect(target_ip_address, app_name, allocator, connection_timeout_seconds) catch |err| {
        std.log.err("Failed to connect to {f}: {t}", .{ target_ip_address, err });
        return err;
    };
    state_ptr.connections[new_peer_id].alive = true;
    state_ptr.active_connections += 1;
}

pub fn requestBlocks(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator, out: *std.Io.Writer) !usize {
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

/// Locks current thread. Spawns new threads and waits for them
pub fn requestNewPeers(state: *State, connection: *const Network.Node.Connection, alloc: std.mem.Allocator) !void {
    var buffer: [max_concurrent_tasks * 105]u8 = undefined; // 105 is empirical and might change
    var buffer_alloc = std.heap.FixedBufferAllocator.init(&buffer);
    var pool: Thread.Pool = undefined;
    try pool.init(.{ .allocator = buffer_alloc.allocator() }); // no deinit cause we're using a stack buffer
    defer {
        while (pool.run_queue.popFirst() != null) {}
        for (pool.threads) |thr| thr.detach();
    }
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

    std.log.info("Connected to {d} new peers\n", .{new_connections_count});
}

/// Caller is responsible for freeing returned string
pub fn getAppFileAbsolutePath(gpa: std.mem.Allocator, filename: []const u8) ![]u8{
    const appdata_dir = try std.fs.getAppDataDir(gpa, app_name);
    defer gpa.free(appdata_dir);
    std.fs.makeDirAbsolute(appdata_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => std.debug.panicExtra(null, "Error calling std.fs.makeDirAbsolute(\"{s}\")", .{appdata_dir}),
    };

    return try std.fmt.allocPrint(gpa, "{s}{c}{s}", .{ appdata_dir, std.fs.path.sep, filename });
}

pub const OpenAppFileOpts = struct {
    /// Clears current file making it empty
    override_existing: bool = false,
};
pub const OpenAppFileError = std.fs.File.OpenError || std.fs.GetAppDataDirError;
/// Caller is reponsible for calling `.close()` on file returned
pub fn openAppFile(gpa: std.mem.Allocator, filename: []const u8, comptime opt: OpenAppFileOpts) OpenAppFileError!std.fs.File {
    const filepath = try getAppFileAbsolutePath(gpa, filename);
    defer gpa.free(filepath);

    std.log.info("accessing {s}...", .{filepath});
    if (opt.override_existing) {
        return try std.fs.createFileAbsolute(filepath, .{});
    } else {
        return std.fs.openFileAbsolute(filepath, .{});
    }
}

