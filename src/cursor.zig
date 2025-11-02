const std = @import("std");
const assert = std.debug.assert;

/// Deprecated. TODO Delete this and replace with std.Io.Reader.fixed()
pub const Cursor = struct {
    data: []const u8,
    index: usize = 0,

    pub fn init(data: []const u8) Cursor {
        return Cursor{ .data = data };
    }

    pub fn ended(self: *Cursor) bool {
        return self.index == self.data.len;
    }

    pub fn assertCanRead(self: *Cursor, n_bytes: usize) void {
        if (self.index + n_bytes > self.data.len) {
            const message = std.fmt.allocPrint(
                std.heap.page_allocator,
                "Trying to read {} bytes at index {} when the data is only {} bytes (only {} could be read)",
                .{ n_bytes, self.index, self.data.len, self.data.len - self.index },
            ) catch "Trying to read too many bytes from the cursor data";
            @panic(message);
        }
    }

    pub fn readInt(self: *Cursor, comptime T: type, comptime endian: std.builtin.Endian) T {
        self.assertCanRead(@sizeOf(T));
        const n_bytes = @divExact(@typeInfo(T).int.bits, 8);
        const ret = std.mem.readInt(T, self.data[self.index..][0..n_bytes], endian);
        self.index += @sizeOf(T);
        return ret;
    }

    pub fn readVarint(self: *Cursor) u32 {
        const first_byte = self.readInt(u8, .little);
        return switch (first_byte) {
            else => @intCast(first_byte),
            0xfd => @intCast(self.readInt(u16, .little)),
            0xfe => @intCast(self.readInt(u24, .little)),
            0xff => @intCast(self.readInt(u32, .little)),
        };
    }

    pub fn readBytes(self: *Cursor, dest: []u8) void {
        self.assertCanRead(dest.len);
        std.mem.copyForwards(u8, dest, self.data[self.index..][0..dest.len]);
        self.index += dest.len;
    }
};
