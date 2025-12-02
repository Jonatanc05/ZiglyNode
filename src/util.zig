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

pub fn writeMyVarInt(stream: *std.Io.Writer, value: u32, endian: std.builtin.Endian) error{WriteFailed}!void {
    switch (value) {
        0...0xfc => {
            try stream.writeInt(u8, @intCast(value), endian);
        },
        0xfd...0x0ffff => {
            try stream.writeByte(0xfd);
            try stream.writeInt(u16, @intCast(value), endian);
        },
        0x10000...0xffffff => {
            try stream.writeByte(0xfe);
            try stream.writeInt(u24, @intCast(value), endian);
        },
        else => {
            try stream.writeByte(0xff);
            try stream.writeInt(u32, @intCast(value), endian);
        },
    }
}

pub fn sizeAsVarint(value: u32) usize {
    return switch (value) {
        0...0xfc => 1,
        0xfd...0x0ffff => 3,
        0x10000...0xffffff => 4,
        else => 5,
    };
}
