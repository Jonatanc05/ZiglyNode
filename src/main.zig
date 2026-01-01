const std = @import("std");
const builtin = @import("builtin");

const ZiglyNode = @import("ziglynode-core.zig");
const SDL = @import("sdl3");

pub const std_options = std.Options{
    .log_level = .info,
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
            @breakpoint();
            std.debug.print("Memory leak detected!\n", .{});
        }
    };
    _ = allocator;

    // var state_ptr: *ZiglyNode.State = try ZiglyNode.State.initAndLoad(allocator);
    // defer state_ptr.deinit(allocator);

    const init_flags = SDL.InitFlags{};
    try SDL.init(init_flags);
    defer SDL.quit(init_flags);
    var fps_capper = SDL.extras.FramerateCapper(f32){ .mode = .{ .limited = 60 } };

    const window = try SDL.video.Window.init(ZiglyNode.app_name, 800, 600, .{
        .resizable = true,
    });
    defer window.deinit();

    var thingy = Thingy {
        .rect = SDL.rect.Rect(i32){
            .h = 120,
            .w = 240,
            .x = 0,
            .y = 0,
        },
        .vel_x = 2,
        .vel_y = 2,
    };

    var quit = false;
    while (!quit) {
        // Logic
        const dt = fps_capper.delay();
        _ = dt;
        const win_bounds = try (try window.getDisplayForWindow()).getBounds();
        if (thingy.rect.x + thingy.rect.w > win_bounds.w or thingy.rect.x < 0) {
            thingy.vel_x = -thingy.vel_x;
        }
        if (thingy.rect.y + thingy.rect.h > win_bounds.h or thingy.rect.y < 0) {
            thingy.vel_y = -thingy.vel_y;
        }
        updateThingy(&thingy);

        // Rendering
        const surface = try window.getSurface();
        try surface.fillRect(null, surface.mapRgb(128, 30, 255));
        try surface.fillRect(thingy.rect, surface.mapRgb(180, 50, 50));
        try window.updateSurface();

        // Events
        while (SDL.events.poll()) |event| {
            switch (event) {
                .quit => quit = true,
                .terminating => quit = true,
                else => {},
            }
        }
    }

    // state_ptr.writeBlockheadersToDisk(allocator);
}

const Thingy = struct {
    rect: SDL.rect.Rect(i32),
    vel_x: i32,
    vel_y: i32,
};

pub fn updateThingy(t: *Thingy) void {
    t.rect.x += t.vel_x;
    t.rect.y += t.vel_y;
}
