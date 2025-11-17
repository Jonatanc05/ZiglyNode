const std = @import("std");

pub fn takeMyVarInt(reader: *std.Io.Reader, endian: std.builtin.Endian) !u32 {
    const first_byte = try reader.takeInt(u8, endian);
    return switch (first_byte) {
        else => @intCast(first_byte),
        0xfd => @intCast(try reader.takeInt(u16, endian)),
        0xfe => @intCast(try reader.takeInt(u24, endian)),
        0xff => @intCast(try reader.takeInt(u32, endian)),
    };
}
