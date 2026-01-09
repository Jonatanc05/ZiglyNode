const std = @import("std");
const builtin = @import("builtin");
const zigly = @import("ziglynode-core.zig");
const dvui = @import("dvui");
const log = std.log.scoped(.zigly_gui);

// To be a dvui App:
// * declare "dvui_app"
// * expose the backend's main function
// * use the backend's log function
pub const dvui_app: dvui.App = .{
    .config = .{
        .options = .{
            .size = .{ .w = 800.0, .h = 600.0 },
            .min_size = .{ .w = 250.0, .h = 350.0 },
            .title = "DVUI App Example",
            .icon = null,
            .window_init_options = .{
                .theme = dvui.Theme.builtin.adwaita_dark,
            },
        },
    },
    .frameFn = AppFrame,
    .initFn = AppInit,
    .deinitFn = AppDeinit,
};
pub const main = dvui.App.main;
pub const panic = dvui.App.panic;
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = dvui.App.logFn,
};

var gpa_instance = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = gpa_instance.allocator();

var state_ptr: *zigly.State = undefined;
var peer_interacting = [1]bool{false} ** zigly.max_connections;

var orig_content_scale: f32 = 1.0;
var warn_on_quit: bool = false;
var warn_on_quit_closing: bool = false;
var prompting_new_connection: bool = false;

pub fn AppInit(win: *dvui.Window) !void {
    orig_content_scale = win.content_scale;

    // Add your own bundled font files...:
    // try dvui.addFont("NOTO", @embedFile("../src/fonts/NotoSansKR-Regular.ttf"), null);

    state_ptr = try zigly.State.initAndLoad(gpa);
}

// Run as app is shutting down before dvui.Window.deinit()
pub fn AppDeinit() void {
    state_ptr.deinit(gpa);
}

// Run each frame to do normal UI
pub fn AppFrame() !dvui.App.Result {
    return frame();
}

pub fn frame() !dvui.App.Result {
    var scaler = dvui.scale(@src(), .{ .scale = &dvui.currentWindow().content_scale, .pinch_zoom = .global }, .{ .rect = .cast(dvui.windowRect()) });
    scaler.deinit();

    {
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .style = .window, .background = true, .expand = .horizontal });
        defer hbox.deinit();

        var m = dvui.menu(@src(), .horizontal, .{});
        defer m.deinit();

        if (dvui.menuItemLabel(@src(), "File", .{ .submenu = true }, .{ .tag = "first-focusable" })) |r| {
            var fw = dvui.floatingMenu(@src(), .{ .from = r }, .{});
            defer fw.deinit();

            if (dvui.menuItemLabel(@src(), "Close Menu", .{}, .{ .expand = .horizontal }) != null) {
                m.close();
            }

            if (dvui.backend.kind != .web) {
                if (dvui.menuItemLabel(@src(), "Exit", .{}, .{ .expand = .horizontal }) != null) {
                    return .close;
                }
            }
        }
    }

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both, .style = .window });
    defer scroll.deinit();

    try peerListWidget();

    _ = dvui.separator(@src(), .{});

    const label = if (dvui.Examples.show_demo_window) "Hide Demo Window" else "Show Demo Window";
    if (dvui.button(@src(), label, .{}, .{ .tag = "show-demo-btn" })) {
        dvui.Examples.show_demo_window = !dvui.Examples.show_demo_window;
    }

    if (dvui.button(@src(), "Debug Window", .{}, .{})) {
        dvui.toggleDebugWindow();
    }

    {
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{});
        defer hbox.deinit();
        dvui.label(@src(), "Pinch Zoom or Scale", .{}, .{});
        if (dvui.buttonIcon(@src(), "plus", dvui.entypo.plus, .{}, .{}, .{})) {
            dvui.currentWindow().content_scale *= 1.1;
        }

        if (dvui.buttonIcon(@src(), "minus", dvui.entypo.minus, .{}, .{}, .{})) {
            dvui.currentWindow().content_scale /= 1.1;
        }

        if (dvui.currentWindow().content_scale != orig_content_scale) {
            if (dvui.button(@src(), "Reset Scale", .{}, .{})) {
                dvui.currentWindow().content_scale = orig_content_scale;
            }
        }
    }

    // look at demo() for examples of dvui widgets, shows in a floating window
    dvui.Examples.demo();

    return .ok;
}

pub fn peerListWidget() !void {
    var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .style = .window, .expand = .horizontal });
    defer vbox.deinit();

    {
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .style = .window, .expand = .vertical });
        defer hbox.deinit();

        const ip_entry = dvui.textEntry(@src(), .{ .placeholder = "77.173.132.140" }, .{});
        const enter_pressed_ip_entry = ip_entry.enter_pressed;
        var ip_str = std.mem.trim(u8, ip_entry.textGet(), &.{' ', '\r', '\n', '\t'});
        if (ip_str.len == 0) ip_str = "77.173.132.140";
        ip_entry.deinit();

        const port_entry = dvui.textEntry(@src(), .{ .placeholder = "8333" }, .{});
        const enter_pressed_port_entry = ip_entry.enter_pressed;
        var port_str = std.mem.trim(u8, port_entry.textGet(), &.{' ', '\r', '\n', '\t'});
        if (port_str.len == 0) port_str = "8333";
        port_entry.deinit();

        if (dvui.button(@src(), "+ new peer", .{}, .{}) or enter_pressed_port_entry or enter_pressed_ip_entry) {
            const port = try std.fmt.parseInt(u16, port_str, 10);
            try zigly.newConnection(state_ptr, gpa, try std.net.Address.resolveIp(ip_str, port));
            dvui.focusWidget(null, null, null);
        }
    }

    dvui.labelNoFmt(@src(), "Peers connected:", .{}, .{ .font = .theme(.heading)});

    for (state_ptr.connections, 0..) |conn, i| {
        if (!conn.alive) continue;
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .style = .window, .background = false, .expand = .horizontal, .id_extra = i });
        defer hbox.deinit();
        dvui.label(@src(), "    {d}: {f} | {s}{s}\n", .{
            i + 1,
            conn.data.peer_address,
            std.mem.trimEnd(u8, &conn.data.user_agent, " "),
            if (conn.data.isFullArchivalNode()) " | Full Archival" else "",
        }, .{
            .font = .theme(.title),
            .id_extra = i,
        });

        var removeButton: dvui.WidgetData = undefined;
        if (dvui.buttonIcon(@src(), "connection_remove", dvui.entypo.trash, .{}, .{ .fill_color = dvui.Color.red }, .{ .id_extra = i, .data_out = &removeButton })) {
            zigly.removeConnection(state_ptr, i) catch |err| {
                log.err("{s}", .{ @errorName(err) });
            };
        }
        dvui.tooltip(@src(), .{ .active_rect = removeButton.borderRectScale().r }, "Remove peer", .{}, .{});

        var interactButton: dvui.WidgetData = undefined;
        if (dvui.buttonIcon(@src(), "connection_interact", dvui.entypo.chat, .{}, .{}, .{ .id_extra = i, .data_out = &interactButton })) {
            peer_interacting[i] = !peer_interacting[i];
        }
        dvui.tooltip(@src(), .{ .active_rect = interactButton.borderRectScale().r }, "Toggle peer interaction", .{}, .{});

        if (peer_interacting[i]) {
            const menu = dvui.menu(@src(), .vertical, .{});
            // var interact_box = dvui.box(@src(), .{ .dir = .horizontal }, .{ .style = .control, .background = true, .expand = .horizontal, .id_extra = i });
            menu.deinit();
        }
    }
    if (state_ptr.active_connections == 0)
        dvui.labelNoFmt(@src(), "    <no entries>\n", .{}, .{});

}

test "tab order" {
    var t = try dvui.testing.init(.{});
    defer t.deinit();

    try dvui.testing.settle(frame);

    try dvui.testing.expectNotFocused("first-focusable");

    try dvui.testing.pressKey(.tab, .none);
    try dvui.testing.settle(frame);

    try dvui.testing.expectFocused("first-focusable");
}

test "open example window" {
    var t = try dvui.testing.init(.{});
    defer t.deinit();

    try dvui.testing.settle(frame);

    // FIXME: The global show_demo_window variable makes tests order dependent
    dvui.Examples.show_demo_window = false;

    try std.testing.expect(dvui.tagGet(dvui.Examples.demo_window_tag) == null);

    try dvui.testing.moveTo("show-demo-btn");
    try dvui.testing.click(.left);
    try dvui.testing.settle(frame);

    try dvui.testing.expectVisible(dvui.Examples.demo_window_tag);
}

// disabling snapshot tests until we figure out a better (less sensitive) way of doing them
//test "snapshot" {
//    // snapshot tests are unstable
//    var t = try dvui.testing.init(.{});
//    defer t.deinit();
//
//    // FIXME: The global show_demo_window variable makes tests order dependent
//    dvui.Examples.show_demo_window = false;
//
//    try dvui.testing.settle(frame);
//
//    // Try swapping the names of ./snapshots/app.zig-test.snapshot-X.png
//    try t.snapshot(@src(), frame);
//
//    try dvui.testing.pressKey(.tab, .none);
//    try dvui.testing.settle(frame);
//
//    try t.snapshot(@src(), frame);
//}
