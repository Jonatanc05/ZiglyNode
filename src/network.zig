const std = @import("std");
const net = std.net;
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const is_windows = @import("builtin").os.tag == .windows;

// managed dependencies
const Cursor = @import("cursor.zig").Cursor;
const Bitcoin = @import("bitcoin.zig");

fn ipv4_as_ipv6(ipv4: [4]u8) [16]u8 {
    return [1]u8{0} ** 10 ++ [2]u8{ 0xff, 0xff } ++ ipv4;
}
fn u32ipv4_as_ipv6(ipv4: u32) [16]u8 {
    const ipv4_bytes: [4]u8 = std.mem.asBytes(&ipv4).*;
    return ipv4_as_ipv6(ipv4_bytes);
}

pub const Protocol = struct {
    pub const current_version = 60002;

    const magic_mainnet = 0xf9beb4d9;
    const magic_testnet = 0x0b110907;
    const header_len = 24;

    pub const Addr = struct {
        time: u32,
        services: u64,
        ip: [16]u8,
        port: u16,
    };

    /// Union for any message accepted by the Bitcoin protocol and its corresponding payload as data
    pub const Message = union(enum) {
        addr: struct {
            count: u32,
            addr_array: []Addr,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try Bitcoin.Aux.writeVarint(writer, self.count);
                for (self.addr_array) |addr| {
                    try writer.writeInt(u32, addr.time, .little);
                    try writer.writeInt(u64, addr.services, .little);
                    try writer.writeAll(&addr.ip);
                    try writer.writeInt(u16, addr.port, .big);
                }
            }

            pub fn parse(data: []const u8, alloc: std.mem.Allocator) anyerror!ParseResult {
                var cursor = Cursor.init(data);
                var res = ParseResult{
                    .value = .{ .addr = undefined },
                    .bytes_read_count = 0,
                };

                res.value.addr.count = cursor.readVarint();
                res.value.addr.addr_array = try alloc.alloc(Protocol.Addr, @intCast(res.value.addr.count));
                for (res.value.addr.addr_array) |*addr| {
                    addr.time = cursor.readInt(u32, .little);
                    addr.services = cursor.readInt(u64, .little);
                    cursor.readBytes(&addr.ip);
                    addr.port = cursor.readInt(u16, .big);
                }

                return res;
            }

            pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
                alloc.free(self.addr_array);
            }
        },
        getaddr: NoPayloadMessage("getaddr"),
        getheaders: struct {
            version: i32 = current_version,
            hash_count: u32,
            hash_start_block: u256,
            /// 0 means "as much as possible"
            hash_final_block: u256,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try writer.writeInt(i32, self.version, .little);
                try Bitcoin.Aux.writeVarint(writer, self.hash_count);
                try writer.writeInt(u256, self.hash_start_block, .little);
                try writer.writeInt(u256, self.hash_final_block, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var cursor = Cursor.init(data);
                var res = ParseResult{
                    .value = .{ .getheaders = undefined },
                    .bytes_read_count = 0,
                };

                res.value.getheaders.version = cursor.readInt(i32, .little);
                res.bytes_read_count += 4;

                const starting_index = cursor.index;
                res.value.getheaders.hash_count = cursor.readVarint();
                res.bytes_read_count += @intCast(cursor.index - starting_index);

                res.value.getheaders.hash_start_block = cursor.readInt(u256, .little);
                res.bytes_read_count += 32;

                res.value.getheaders.hash_final_block = cursor.readInt(u256, .little);
                res.bytes_read_count += 32;

                return res;
            }
        },
        headers: struct {
            data: []Bitcoin.Block,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try Bitcoin.Aux.writeVarint(writer, @intCast(self.data.len));
                for (self.data) |block| {
                    var buffer: [80]u8 = undefined;
                    const serialization = block.serialize(&buffer);
                    try writer.writeAll(serialization);
                    try writer.writeInt(u8, 0, .little);
                }
            }

            pub fn parse(data: []const u8, alloc: std.mem.Allocator) anyerror!ParseResult {
                var cursor = Cursor.init(data);
                const count = cursor.readVarint();
                const blocks = try alloc.alloc(Bitcoin.Block, count);
                for (blocks) |*block| {
                    block.* = Bitcoin.Block.parse(cursor.data[cursor.index..][0..80]);
                    cursor.index += 80;
                    std.debug.assert(cursor.readInt(u8, .little) == 0);
                }
                const total_read: u32 = @intCast(cursor.index);

                return .{
                    .value = .{ .headers = .{ .data = blocks } },
                    .bytes_read_count = total_read,
                };
            }
        },
        ping: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try writer.writeInt(u64, self.nonce, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var cursor = Cursor.init(data);

                var res = ParseResult{
                    .value = Message{ .ping = .{ .nonce = undefined } },
                    .bytes_read_count = 0,
                };

                const nonce = cursor.readInt(u64, .little);
                res.value.ping.nonce = nonce;
                res.bytes_read_count += 8;

                return res;
            }
        },
        pong: struct {
            nonce: u64,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try writer.writeInt(u64, self.nonce, .little);
            }

            pub fn parse(data: []const u8, unused: std.mem.Allocator) anyerror!ParseResult {
                _ = unused;
                var cursor = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .pong = .{ .nonce = undefined } },
                    .bytes_read_count = 0,
                };

                const nonce = cursor.readInt(u64, .little);
                res.value.pong.nonce = nonce;
                res.bytes_read_count += 8;

                return res;
            }
        },
        verack: NoPayloadMessage("verack"),
        version: struct {
            version: i32 = current_version,
            // @TODO make it BIP159 compliant (https://github.com/bitcoin/bips/blob/master/bip-0159.mediawiki)
            services: u64 = 0,
            timestamp: i64,
            receiver_services: u64 = 0,
            receiver_ip: [16]u8 = [1]u8{0} ** 16,
            receiver_port: u16 = 8333,
            sender_services: u64 = 0,
            sender_ip: [16]u8 = ipv4_as_ipv6([4]u8{ 127, 0, 0, 1 }),
            sender_port: u16 = 8333,
            nonce: u64 = 0x1f297b45,
            user_agent: []const u8,
            start_height: i32 = 0,
            relay: bool = false,

            pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                try writer.writeInt(i32, self.version, .little);
                try writer.writeInt(u64, self.services, .little);
                try writer.writeInt(i64, self.timestamp, .little);

                try writer.writeInt(u64, self.receiver_services, .little);
                try writer.writeAll(&self.receiver_ip);
                try writer.writeInt(u16, self.receiver_port, .big);

                try writer.writeInt(u64, self.sender_services, .little);
                try writer.writeAll(&self.sender_ip);
                try writer.writeInt(u16, self.sender_port, .big);

                try writer.writeInt(u64, self.nonce, .little);
                std.debug.assert(self.user_agent.len < 0xfd); // It's supposed to be read as varint
                try writer.writeInt(u8, @intCast(self.user_agent.len), .little);
                try writer.writeAll(self.user_agent);
                try writer.writeInt(i32, self.start_height, .little);

                try writer.writeInt(u8, if (self.relay) 1 else 0, .big);
            }

            pub fn parse(data: []const u8, alloc: std.mem.Allocator) anyerror!ParseResult {
                var cursor = Cursor.init(data);
                var res = ParseResult{
                    .value = Message{ .version = .{ .timestamp = 0, .user_agent = undefined } },
                    .bytes_read_count = 0,
                };

                var out = &res.value.version;

                out.version = cursor.readInt(i32, .little);
                res.bytes_read_count += 4;
                out.services = cursor.readInt(u64, .little);
                out.timestamp = cursor.readInt(i64, .little);
                res.bytes_read_count += 8 * 2;

                out.receiver_services = cursor.readInt(u64, .little);
                res.bytes_read_count += 8;

                cursor.readBytes(&out.receiver_ip);
                res.bytes_read_count += out.receiver_ip.len;

                out.receiver_port = cursor.readInt(u16, .little);
                res.bytes_read_count += 2;

                out.sender_services = cursor.readInt(u64, .little);
                res.bytes_read_count += 8;

                cursor.readBytes(&out.sender_ip);
                res.bytes_read_count += out.sender_ip.len;
                out.sender_port = cursor.readInt(u16, .little);
                res.bytes_read_count += 2;

                out.nonce = cursor.readInt(u64, .little);
                res.bytes_read_count += 8;

                const user_agent_len = cursor.readInt(u8, .little);
                res.bytes_read_count += 1;

                var buffer: [256]u8 = undefined;
                cursor.readBytes(buffer[0..user_agent_len]);
                out.user_agent = try alloc.dupe(u8, buffer[0..user_agent_len]);
                res.bytes_read_count += user_agent_len;

                out.start_height = cursor.readInt(i32, .little);
                res.bytes_read_count += 4;
                out.relay = (cursor.readInt(u8, .little)) > 0;
                res.bytes_read_count += 1;

                return res;
            }

            pub fn deinit(self: @This(), alloc: std.mem.Allocator) void {
                alloc.free(self.user_agent);
            }
        },

        // Enforce function signatures on each union tag (each protocol command)
        comptime {
            const T = Protocol.Message;

            const ExpectedFunction = struct {
                is_mandatory: bool,
                name: []const u8,
                return_type: type,
                params: []const type,
            };
            const expected_functions = .{
                ExpectedFunction{
                    .is_mandatory = true,
                    .name = "serialize",
                    .return_type = anyerror!void,
                    .params = &[_]type{ void, *std.Io.Writer },
                },
                ExpectedFunction{
                    .is_mandatory = true,
                    .name = "parse",
                    .return_type = anyerror!Protocol.Message.ParseResult,
                    .params = &[_]type{ []const u8, std.mem.Allocator },
                },
                ExpectedFunction{
                    .is_mandatory = false,
                    .name = "deinit",
                    .return_type = void,
                    .params = &[_]type{ void, std.mem.Allocator },
                },
            };

            for (@typeInfo(T).@"union".fields) |field| {
                for (expected_functions) |expected| {
                    // check existance
                    if (!@hasDecl(field.type, expected.name)) {
                        if (expected.is_mandatory) {
                            var buf: [200]u8 = undefined;
                            @compileError(std.fmt.bufPrint(&buf, "A {s} function is required for {s}.{s}", .{ expected.name, @typeName(T), field.name }) catch "E879234");
                        } else continue;
                    }

                    const fn_decl = @field(field.type, expected.name);
                    const fn_info = @typeInfo(@TypeOf(fn_decl)).@"fn";
                    const SignatureMismatch = struct {
                        fn throw() void {
                            var buf: [300]u8 = undefined;
                            @compileError(std.fmt.bufPrint(
                                &buf,
                                "The function {s}.{s}.{s} has the wrong signature. Should be: fn {s}({d}) {s} (also check parameter types)",
                                .{ @typeName(T), field.name, expected.name, expected.name, expected.params.len, @typeName(expected.return_type) },
                            ) catch "E1293485");
                        }
                    };

                    // check return_type
                    if (fn_info.return_type != expected.return_type)
                        SignatureMismatch.throw();

                    if (fn_info.params.len != expected.params.len)
                        SignatureMismatch.throw();

                    for (fn_info.params, expected.params) |p_actual, p_expected| {
                        if (p_expected == void) continue; // void means ignore
                        if (p_actual.type != p_expected)
                            SignatureMismatch.throw();
                    }
                }
            }
        }

        pub fn NoPayloadMessage(comptime tag_name: []const u8) type {
            return struct {
                pub fn serialize(self: @This(), writer: *std.Io.Writer) anyerror!void {
                    _ = self;
                    _ = writer;
                }

                pub fn parse(unused: []const u8, _unused: std.mem.Allocator) anyerror!ParseResult {
                    _ = unused;
                    _ = _unused;
                    return .{ .value = @unionInit(Message, tag_name, .{}), .bytes_read_count = 8 };
                }
            };
        }

        /// Includes the protocol headers (https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure)
        pub fn serialize(self: *const Message, buffer: []u8) ![]u8 {
            var writer: std.Io.Writer = .fixed(buffer);

            // magic
            try writer.writeInt(u32, Protocol.magic_mainnet, .big);

            // command
            try writer.writeAll(&command_bytes: {
                const command = @tagName(self.*);
                var command_bytes = [_]u8{0} ** 12;
                std.mem.copyForwards(u8, command_bytes[0..], command);
                break :command_bytes command_bytes;
            });

            // payload
            std.debug.assert(writer.end == 16);
            // intentionally skipping 8 bytes cause we need payload to compute them
            var payload_buffer = buffer[24..];
            //var payload_stream = std.io.fixedBufferStream(payload_buffer);
            var payload_stream: std.Io.Writer = .fixed(payload_buffer);
            switch (self.*) {
                inline else => |field| try field.serialize(&payload_stream),
            }
            const payload_size = payload_stream.end;

            // length
            try writer.writeInt(u32, @intCast(payload_size), .little);

            // checksum
            var hash: [32]u8 = undefined;
            Sha256.hash(payload_buffer[0..payload_size], &hash, .{});
            Sha256.hash(&hash, &hash, .{});
            try writer.writeAll(hash[0..4]);

            return buffer[0 .. writer.end + payload_size];
        }

        const ParseResult = struct { value: Message, bytes_read_count: u32 };

        pub fn parse(bytes: []u8, alloc: std.mem.Allocator) !ParseResult {
            var reader: std.Io.Reader = .fixed(bytes);
            var res: ParseResult = .{
                .value = undefined,
                .bytes_read_count = 0,
            };
            defer res.bytes_read_count = @intCast(reader.seek);

            const magic = try reader.takeInt(u32, .big);
            if (magic != magic_mainnet and magic != magic_testnet) // might try to assert the magic read and the current context in the future
                return error.MagicNumberExpected;

            const command = try reader.takeArray(12);

            const payload_size = try reader.takeInt(u32, .little);

            const checksum_read = try reader.takeArray(4);

            const payload_slice = bytes[reader.seek..][0..payload_size];
            // checksum validation
            {
                var hash: [32]u8 = undefined;
                Sha256.hash(payload_slice, &hash, .{});
                Sha256.hash(&hash, &hash, .{});
                const calculated_checksum: []u8 = hash[0..4];
                if (!std.mem.eql(u8, checksum_read, calculated_checksum)) {
                    return error.ChecksumMismatch;
                }
            }

            const first_zero_index: usize = for (command, 0..) |c, i| {
                if (c == 0) break i;
            } else 12;
            const tag_name = command[0..first_zero_index];
            var supported_command = false;
            inline for (@typeInfo(Message).@"union".fields) |field| {
                if (std.mem.eql(u8, field.name, tag_name)) {
                    supported_command = true;
                    const msg_parse_result = try field.type.parse(payload_slice, alloc);
                    res.value = msg_parse_result.value;
                    res.bytes_read_count += msg_parse_result.bytes_read_count;
                }
            }

            // shouldn't be an error condition but we want temporarily be sure we implented common commands
            if (!supported_command) return error.UnsupportedCommandReceived;

            return res;
        }

        pub fn deinit(self: Message, alloc: std.mem.Allocator) void {
            inline for (@typeInfo(Message).@"union".fields) |field| {
                switch (self) {
                    inline else => |field_instance| {
                        if (@hasDecl(field.type, "deinit")) {
                            if (@TypeOf(field_instance) == field.type)
                                field_instance.deinit(alloc);
                        }
                    },
                }
            }
        }
    };

    pub fn checksum(bytes: []u8) [4]u8 {
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        Sha256.hash(&hash, &hash, .{});
        return hash[0..4];
    }
};

pub const Node = struct {
    pub const Connection = struct {
        peer_address: net.Address,
        peer_version: i32,
        stream: net.Stream,
        handshaked: bool,
        user_agent: [30]u8,
    };

    /// This function blocks current thread for, at most, `timeout_seconds`
    pub fn connect(address: net.Address, self_user_agent: []const u8, alloc: std.mem.Allocator, timeout_seconds: comptime_int) !Connection {
        const posix = std.posix;
        const sockfd = posix.socket(address.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch |err| {
            std.log.err("Failed to create socket for {f}: {t}", .{ address, err });
            return error.ConnectionError;
        };
        const sock_connect = struct {
            pub fn sock_connect(_sockfd: posix.socket_t, _address: net.Address) !void {
                posix.connect(_sockfd, &_address.any, _address.getOsSockLen()) catch |err| switch (err) {
                    posix.ConnectError.WouldBlock => {},
                    else => {
                        std.log.err("Failed to connect to {f}: {t}", .{ _address, err });
                        return error.ConnectionError;
                    },
                };
            }
        }.sock_connect;

        const start_timestamp = std.time.milliTimestamp();
        if (is_windows) {
            const ws2 = std.os.windows.ws2_32;
            var set_non_blocking: c_ulong = 1;
            const ioctlsocket_result = ws2.ioctlsocket(sockfd, ws2.FIONBIO, &set_non_blocking);
            std.debug.assert(ioctlsocket_result == 0);
            try sock_connect(sockfd, address);

            var fds = [1]ws2.pollfd{
                ws2.pollfd{ .fd = sockfd, .events = ws2.POLL.OUT, .revents = 0 },
            };
            var sockets_affected = ws2.WSAPoll(&fds, @intCast(fds.len), 0);
            while (sockets_affected == 0 and std.time.milliTimestamp() < start_timestamp + (timeout_seconds * 1000)) {
                std.Thread.sleep(100_000_000);
                sockets_affected = ws2.WSAPoll(&fds, @intCast(fds.len), 0);
            }
            if (fds[0].revents & ws2.POLL.OUT == 0) {
                posix.close(sockfd);
                return error.Timeout;
            }
        } else {
            var flags = try posix.fcntl(sockfd, posix.F.GETFL, 0);
            flags |= 1 << @bitOffsetOf(posix.O, "NONBLOCK");
            _ = try posix.fcntl(sockfd, posix.F.SETFL, flags);
            try sock_connect(sockfd, address);
            var fds = [1]posix.pollfd{
                posix.pollfd{
                    .fd = sockfd,
                    .events = posix.POLL.OUT,
                    .revents = 0,
                },
            };
            var sockets_affected = try posix.poll(&fds, 0);
            while (sockets_affected == 0 and std.time.milliTimestamp() < start_timestamp + (timeout_seconds * 1000)) {
                std.Thread.sleep(100_000_000);
                sockets_affected = try posix.poll(&fds, 0);
            }
            if (fds[0].revents & posix.POLL.OUT == 0) {
                posix.close(sockfd);
                return error.ConnectionError;
            }
            flags &= ~(@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK")));
            _ = try posix.fcntl(sockfd, posix.F.SETFL, flags);
        }
        const stream = std.net.Stream{ .handle = sockfd };

        var connection = Connection{
            .peer_address = address,
            .peer_version = 0,
            .stream = stream,
            .handshaked = false,
            .user_agent = undefined,
        };

        // Start handshake
        const timestamp = std.time.timestamp();
        try Node.sendMessage(&connection, .{
            .version = .{
                .timestamp = timestamp,
                .nonce = @intCast(timestamp),
                .start_height = 0,
                .user_agent = self_user_agent,
            },
        });

        // Read answer
        var received: [2]Protocol.Message = undefined;

        received[0] = try Node.readMessage(&connection, alloc);
        defer received[0].deinit(alloc);

        received[1] = try Node.readMessage(&connection, alloc);
        defer received[1].deinit(alloc);

        // Information to obtain
        var verack_received: bool = false;
        var version_received: ?i32 = null;
        var user_agent_received: [30]u8 = [1]u8{'.'} ++ [1]u8{' '} ** 29;
        for (received) |msg| {
            switch (msg) {
                Protocol.Message.version => |v_msg| {
                    if (v_msg.version < Protocol.current_version)
                        return error.VersionMismatch;
                    for (v_msg.user_agent, 0..) |ch, i| {
                        if (i >= user_agent_received.len) break;
                        user_agent_received[i] = ch;
                    }
                    version_received = v_msg.version;
                },
                Protocol.Message.verack => verack_received = true,
                else => return error.UnexpectedMessageOnHandshake,
            }
        }

        if (version_received != null and verack_received) {
            try Node.sendMessage(&connection, Protocol.Message{ .verack = .{} });
            connection.peer_version = version_received.?;
            connection.handshaked = true;
            connection.user_agent = user_agent_received;
            return connection;
        }

        return error.HandshakeFailed;
    }

    pub fn sendMessage(connection: *const Node.Connection, message: Protocol.Message) !void {
        var buffer: [1024]u8 = undefined;
        const data = try message.serialize(&buffer);
        std.log.debug("Sending message \"{s}\" with following payload ({d} bytes):", .{ @tagName(message), data.len - Protocol.header_len });
        const debug_clip_index = 1000;
        if (data.len > (debug_clip_index + Protocol.header_len)) {
            std.log.debug("{x}... (+{d} bytes)", .{ data[Protocol.header_len..][0..debug_clip_index], data.len - debug_clip_index - Protocol.header_len });
        } else {
            std.log.debug("{x}", .{data[Protocol.header_len..]});
        }

        var writer_concrete = connection.stream.writer(&.{});
        var writer = &writer_concrete.interface;
        writer.writeAll(data) catch |err| {
           std.log.err("Failed to write to socket at {f}: {t}", .{ connection.peer_address, err });
           return error.SendError;
        };
    }

    /// Synchronously waits to receive bytes. Caller should call .deinit() on returned value
    pub fn readMessage(connection: *const Connection, alloc: std.mem.Allocator) !Protocol.Message {
        const header_len = Protocol.header_len;
        var buffer = ([1]u8{0} ** header_len) ++ ([1]u8{0} ** (1024 * 256));
        var header_slice = buffer[0..header_len];

        var reader_concrete = connection.stream.reader(&.{});
        var reader = reader_concrete.interface();
        const read_count1 = reader.readSliceShort(header_slice) catch |err| {
            std.log.err("Failed to read from socket at {f}: {t}", .{ connection.peer_address, err });
            return error.ReceiveError;
        };
        if (read_count1 < header_len) return error.NoMessages;
        std.debug.assert(read_count1 == header_len);
        const payload_length = std.mem.readInt(u32, header_slice[16..][0..4], .little);
        const payload_slice = buffer[header_len..][0..payload_length];

        const read_count2 = reader.readSliceShort(payload_slice) catch |err| {
            std.log.err("Failed to read from socket at {f}: {t}", .{ connection.peer_address, err });
            return error.ReceiveError;
        };
        if (read_count2 < payload_length) return error.ReceiveError;

        std.log.debug("Received message \"{s}\" with the following payload ({d} bytes):", .{ header_slice[4..16], payload_length });
        const debug_clip_index = 1000;
        if (payload_slice.len > debug_clip_index) {
            std.log.debug("{s}... (+{x} bytes)", .{ payload_slice[0..debug_clip_index], payload_slice.len - debug_clip_index });
        } else {
            std.log.debug("{s}", .{payload_slice});
        }

        const result = try Protocol.Message.parse(buffer[0..], alloc);
        return result.value;
    }

    /// Should be only temporary, we might (probably should) have evented messages
    pub fn readUntilMessage(connection: *const Connection, comptime tag: @typeInfo(Protocol.Message).@"union".tag_type.?, alloc: std.mem.Allocator) !Protocol.Message {
        while (true) {
            if (readMessage(connection, alloc)) |msg| {
                switch (msg) {
                    Protocol.Message.ping => |ping| {
                        try Node.sendMessage(
                            connection,
                            Protocol.Message{ .pong = .{ .nonce = ping.nonce } },
                        );
                    },
                    tag => return msg,

                    // @TODO have experienced being answered with inv

                    else => {
                        std.debug.print("Unexpected command: {s}\n", .{@tagName(msg)});
                    },
                }
                msg.deinit(alloc);
            } else |err| switch (err) {
                error.UnsupportedCommandReceived => {
                    std.debug.print("Unexpected and unsupported command received\n", .{});
                },
                else => return err,
            }
        }
    }
};

//#region TESTS #########################################################################

const expect = std.testing.expect;
const t_alloc = std.testing.allocator;

test "protocol: message serialization" {
    const message = Protocol.Message{ .ping = .{ .nonce = 0x127f } };
    var buffer = [_]u8{0} ** 32;
    const res = try message.serialize(&buffer);
    try expect(res.len == 32);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xF9, 0xBE, 0xB4, 0xD9, 0x70, 0x69, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x4E, 0x6E, 0xDE, 0x71, 0x7f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        res,
    );

    const parsed_res = (try Protocol.Message.parse(res, t_alloc)).value;
    var buffer2 = [_]u8{0} ** 32;
    const serialized_parsed_res = try parsed_res.serialize(&buffer2);

    try std.testing.expectEqualSlices(
        u8,
        res,
        serialized_parsed_res,
    );
}

test "protocol: handshake and version" {
    //const host = "58.96.123.120"; // from bitcoin core's nodes_main.txt
    const host = "74.220.255.190"; // from bitcoin core's nodes_main.txt
    //const host = "77.173.132.140"; // from bitcoin core's nodes_main.txt
    const port = 8333;
    const address = try net.Address.resolveIp(host, port);
    const connection = try Node.connect(address, "networkzig-test", t_alloc, 15);
    try expect(connection.handshaked);
    try expect(connection.peer_version > 0);
}

//#endregion
