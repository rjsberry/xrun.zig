// The contents of this file is dual-licensed under the MIT or 0BSD license.

//! The `xrun` runner.
//!
//! This program wraps OpenOCD and optionally GDB to provide a streamlined
//! interface for working with firmware in Zig.
//!
//! It is compiled and called into by the `xrun` library component in Zig build
//! systems (aka `build.zig`) to enable you to run `zig build xrun` to cross
//! compile and flash your firmare.
//!
//! The runner supports 3 subcommands:
//!
//! * `monitor` -- watch RTT output (default)
//! * `flash` -- just flash the firmware then exit
//! * `gdb` -- flash the firmware then launch an interactive GDB session

const std = @import("std");

const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const process = std.process;
const time = std.time;
const zig = std.zig;

const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const Ast = zig.Ast;

pub fn main() void {
    const allocator = heap.page_allocator;

    const term = run(allocator) catch |err| {
        unwrap(void, printError(allocator, err));
        process.exit(1);
    };

    process.exit(term);
}

/// Runs the application.
fn run(allocator: Allocator) !u8 {
    var args = try process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    const zon_path = popArg(&args);
    const elf_path = popArg(&args);

    var cfg = try Config.parse(allocator, zon_path);
    defer cfg.deinit(allocator);

    var cmd: Command = .monitor;
    if (args.next()) |arg| {
        if (mem.eql(u8, arg, "flash")) {
            cmd = .flash;
        } else if (mem.eql(u8, arg, "gdb")) {
            cmd = .gdb;
        } else if (mem.eql(u8, arg, "monitor")) {
            // already default cmd
        } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            unwrap(void, printHelp());
            process.exit(0);
        } else {
            exitUsage();
        }
    }

    if (args.next() != null) {
        exitUsage();
    }

    var openocd_args = try OpenocdArgs.init(
        allocator,
        &cfg,
        elf_path,
        cmd,
    );
    defer openocd_args.deinit();

    var openocd_rdr = try OpenocdReader.init(
        allocator,
        &openocd_args,
    );
    defer _ = unwrap(process.Child.Term, openocd_rdr.child.wait());
    defer openocd_rdr.deinit();

    return switch (cmd) {
        .flash => try runFlash(&openocd_rdr),
        .gdb => try runGdb(allocator, &openocd_rdr, &cfg, elf_path),
        .monitor => try runMonitor(allocator, &openocd_rdr, &cfg, elf_path),
    };
}

/// Runs the `flash` subcommand.
fn runFlash(openocd_rdr: *OpenocdReader) !u8 {
    while (try openocd_rdr.next()) |line| {
        if (mem.startsWith(u8, line, "Error")) {
            var std_err = io.getStdErr().writer();
            unwrap(void, std_err.print("{s}\n", .{line}));
            return 1;
        }
        if (mem.eql(u8, line, "shutdown command invoked")) {
            break;
        }
    }

    return 0;
}

/// Runs the `gdb` subcommand.
fn runGdb(
    allocator: Allocator,
    openocd_rdr: *OpenocdReader,
    cfg: *const Config,
    elf_path: []const u8,
) !u8 {
    defer _ = unwrap(process.Child.Term, openocd_rdr.child.kill());

    while (try openocd_rdr.next()) |line| {
        if (mem.startsWith(u8, line, "Error")) {
            var std_err = io.getStdErr().writer();
            unwrap(void, std_err.print("{s}\n", .{line}));
            return 1;
        }
        if (mem.endsWith(u8, line, "gdb connections")) {
            break;
        }
    }

    const gdb_args = [_][]const u8{
        cfg.gdb.asStr(),
        "-q",
        "-ex",
        "target extended-remote :3333",
        "-ex",
        "set print asm-demangle on",
        "-ex",
        "break _reset",
        "-ex",
        "load",
        "-ex",
        "stepi",
        elf_path,
    };

    // todo: fix ctrl+c
    var gdb = process.Child.init(&gdb_args, allocator);
    gdb.stdin_behavior = .Inherit;
    gdb.stdout_behavior = .Inherit;
    gdb.stderr_behavior = .Inherit;
    _ = try gdb.spawnAndWait();

    return 0;
}

/// Runs the `monitor` subcommand.
fn runMonitor(
    allocator: Allocator,
    openocd_rdr: *OpenocdReader,
    cfg: *const Config,
    elf_path: []const u8,
) !u8 {
    defer _ = unwrap(process.Child.Term, openocd_rdr.child.kill());

    while (try openocd_rdr.next()) |line| {
        if (mem.startsWith(u8, line, "Error")) {
            var std_err = io.getStdErr().writer();
            unwrap(void, std_err.print("{s}\n", .{line}));
            process.exit(1);
        }
        if (mem.endsWith(u8, line, "rtt connections")) {
            break;
        }
    }

    const gdb_args = [_][]const u8{
        cfg.gdb.asStr(),
        "-q",
        "--batch",
        "-ex",
        "target extended-remote :3333",
        "-ex",
        "set print asm-demangle on",
        "-ex",
        "load",
        "-ex",
        "continue",
        "-ex",
        "x/s msg.ptr",
        "-ex",
        "backtrace",
        elf_path,
    };

    var gdb = process.Child.init(&gdb_args, allocator);
    gdb.stdin_behavior = .Ignore;
    gdb.stdout_behavior = .Pipe;
    gdb.stderr_behavior = .Pipe;
    _ = try gdb.spawn();

    var gdb_poller = io.poll(allocator, enum { stdout }, .{
        .stdout = gdb.stdout.?,
    });
    defer gdb_poller.deinit();

    var stream_buf = ArrayList(u8).init(allocator);
    defer stream_buf.deinit();

    const addr = net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 9999);
    var tcp_stream = try net.tcpConnectToAddress(addr);
    var tv = mem.zeroInit(os.timeval, .{ .tv_usec = 500000 });
    const tv_bytes: *const [@sizeOf(@TypeOf(tv))]u8 = @ptrCast(&tv);
    try os.setsockopt(
        tcp_stream.handle,
        os.SOL.SOCKET,
        os.SO.RCVTIMEO,
        tv_bytes,
    );

    var std_out = io.getStdOut().writer();
    var rdr = tcp_stream.reader();
    var wtr = stream_buf.writer();

    while (true) {
        const gdb_events = try os.poll(&gdb_poller.poll_fds, 0);
        if (gdb_poller.poll_fds[0].revents & os.POLL.HUP != 0) {
            break;
        }

        rdr.streamUntilDelimiter(wtr, '\n', null) catch |err| switch (err) {
            error.WouldBlock => {},
            else => |_| return err,
        };

        // If GDB hasn't connected to OpenOCD we throw away any RTT messages.
        //
        // There's a bit of a race condition where OpenOCD can start sending
        // us RTT messages before GDB connects. When GDB resets the firmware
        // this can cause us to receive the same RTT messages towards the
        // start of the firmware twice.
        if (gdb_events != 0 and stream_buf.items.len != 0) {
            unwrap(void, std_out.print("{s}\n", .{stream_buf.items}));
        }
        stream_buf.clearRetainingCapacity();
    }

    // Read all of GDBs stdout.
    var amt: usize = 512;
    while (amt != 0) {
        var q = &gdb_poller.fifos[0];
        var buf = try q.writableWithSize(amt);
        amt = try os.read(gdb_poller.poll_fds[0].fd, buf);
        q.update(amt);
    }

    switch (try gdb.wait()) {
        .Exited => |code| if (code != 0) return error.GdbFailed,
        else => return error.GdbFailed,
    }

    var gdb_lines = mem.split(u8, gdb_poller.fifos[0].buf, "\n");
    while (gdb_lines.next()) |line| {
        if (mem.startsWith(u8, line, "Program received signal SIGTRAP")) {
            break;
        }
    }

    const trapped = gdb_lines.next() orelse @panic("parse gdb output");
    const panicked = mem.startsWith(u8, trapped, "builtin.default_panic");

    if (!panicked) {
        return 0;
    }

    _ = gdb_lines.next();
    const panic_output = gdb_lines.next() orelse @panic("parse gdb output");
    var panic_output_iter = mem.splitScalar(u8, panic_output, '"');
    _ = panic_output_iter.next();
    const panic_msg = panic_output_iter.next() orelse @panic("parse gdb");

    var std_err = io.getStdErr().writer();

    unwrap(void, std_err.print(
        "\n\x1b[31;1merror:\x1b[0m firmware panicked at: \x1b[36m{s}\x1b[0m\n",
        .{panic_msg},
    ));

    while (gdb_lines.next()) |line| {
        if (!mem.startsWith(u8, line, "#")) {
            break;
        }
        unwrap(void, std_err.print("{s}\n", .{line}));
    }

    unwrap(void, std_err.writeAll("\n"));

    return 1;
}

/// Subcommands that `xrun.zig` can execute.
const Command = enum {
    /// Only flash the target (does not hold terminal open with an RTT stream).
    flash,
    /// Launch a GDB session.
    gdb,
    /// Monitor an RTT stream from the firmware (default command).
    monitor,
};

/// The `xrun.zig.zon` configuration.
///
/// This tells us which OpenOCD scripts to import.
const Config = struct {
    /// The OpenOCD target: `target/{}.cfg`.
    target: []const u8,
    /// The OpenOCD interface: `interface/{}.cfg`.
    interface: []const u8,
    /// Allows overriding the default OpenOCD adapter speed.
    adapter_speed: ?usize,
    /// The gdb binary to use.
    gdb: DynStr,

    /// Parses the config from an (absolute) path to an `xrun.zig.zon`.
    fn parse(allocator: Allocator, zon_path: []const u8) !Config {
        const zon = try fs.cwd().readFileAllocOptions(
            allocator,
            zon_path,
            4096,
            null,
            1,
            0,
        );
        defer allocator.free(zon);

        var ast = try Ast.parse(allocator, zon, .zon);
        defer ast.deinit(allocator);

        const node_datas = ast.nodes.items(.data);
        const main_node_index = node_datas[0].lhs;

        var buf: [2]Ast.Node.Index = undefined;
        const struct_init = ast.fullStructInit(&buf, main_node_index) orelse {
            return error.ZonParseFailure;
        };

        var cfg = Config{
            .target = undefined,
            .interface = undefined,
            .adapter_speed = null,
            .gdb = DynStr{ .static = "gdb-multiarch" },
        };

        var have_target = false;
        var have_interface = false;

        for (struct_init.ast.fields) |field_init| {
            const val_token = ast.firstToken(field_init);
            const name_token = val_token - 2;
            const field_name = ast.tokenSlice(name_token);

            if (mem.eql(u8, field_name, "target")) {
                const token = ast.tokenSlice(val_token);
                cfg.target = try parseStrLit(allocator, token);
                have_target = true;
            } else if (mem.eql(u8, field_name, "interface")) {
                const token = ast.tokenSlice(val_token);
                cfg.interface = try parseStrLit(allocator, token);
                have_interface = true;
            } else if (mem.eql(u8, field_name, "adapter_speed")) {
                const adapter_speed = ast.tokenSlice(val_token);
                cfg.adapter_speed = try fmt.parseInt(usize, adapter_speed, 10);
            } else if (mem.eql(u8, field_name, "gdb")) {
                const token = ast.tokenSlice(val_token);
                cfg.gdb = DynStr{
                    .dynamic = try parseStrLit(allocator, token),
                };
            }
        }

        if (!have_target or !have_interface) {
            return error.ParseError;
        }

        return cfg;
    }

    /// Deallocates managed config memory.
    fn deinit(self: *Config, allocator: Allocator) void {
        allocator.free(self.target);
        allocator.free(self.interface);
        switch (self.gdb) {
            .dynamic => |str| allocator.free(str),
            else => {},
        }
    }
};

/// Tries to parse a token as a string literal.
fn parseStrLit(allocator: Allocator, token: []const u8) ![]const u8 {
    var str_buf = ArrayList(u8).init(allocator);
    defer str_buf.deinit();
    const res = try zig.string_literal.parseWrite(str_buf.writer(), token);
    switch (res) {
        .success => {},
        .failure => |_| return error.ParseError,
    }
    return try allocator.dupe(u8, str_buf.items);
}

/// Tries to parse a token as a boolean literal.
fn parseBoolLit(token: []const u8) !bool {
    if (mem.eql(u8, token, "true")) {
        return true;
    } else if (mem.eql(u8, token, "false")) {
        return false;
    } else {
        return error.ParseError;
    }
}

/// Tag for `DynStr`.
const DynStrTag = enum {
    static,
    dynamic,
};

/// A possibly dynamic string, aka does it need to be deallocated?
const DynStr = union(DynStrTag) {
    static: []const u8,
    dynamic: []const u8,

    fn asStr(self: DynStr) []const u8 {
        switch (self) {
            inline else => |str| return str,
        }
    }
};

/// Arguments to OpenOCD.
const OpenocdArgs = struct {
    allocator: Allocator,
    args: ArrayList(DynStr),

    fn init(
        allocator: Allocator,
        cfg: *const Config,
        elf_path: []const u8,
        cmd: Command,
    ) !OpenocdArgs {
        var args = ArrayList(DynStr).init(allocator);

        const interface_arg = try fmt.allocPrint(
            allocator,
            "interface/{s}.cfg",
            .{cfg.interface},
        );

        const target_arg = try fmt.allocPrint(
            allocator,
            "target/{s}.cfg",
            .{cfg.target},
        );

        try args.appendSlice(&[_]DynStr{
            DynStr{ .static = "openocd" },
            DynStr{ .static = "-f" },
            DynStr{ .dynamic = interface_arg },
            DynStr{ .static = "-f" },
            DynStr{ .dynamic = target_arg },
        });

        if (cfg.adapter_speed) |arg| {
            const adapter_speed_arg = try fmt.allocPrint(
                allocator,
                "adapter speed {}",
                .{arg},
            );
            try args.appendSlice(&[_]DynStr{
                DynStr{ .static = "-c" },
                DynStr{ .dynamic = adapter_speed_arg },
            });
        }

        const program_arg = if (cmd == .flash)
            try fmt.allocPrint(
                allocator,
                "program {s} verify reset exit",
                .{elf_path},
            )
        else
            try fmt.allocPrint(
                allocator,
                "program {s} verify reset",
                .{elf_path},
            );

        try args.appendSlice(&[_]DynStr{
            DynStr{ .static = "-c" },
            DynStr{ .static = "init" },
            DynStr{ .static = "-c" },
            DynStr{ .dynamic = program_arg },
        });

        if (cmd == .monitor) {
            try args.appendSlice(&[_]DynStr{
                DynStr{ .static = "-c" },
                DynStr{ .static = "halt" },
                DynStr{ .static = "-c" },
                DynStr{ .static = "rtt server start 9999 0" },
            });

            if (try findRttSymbolAddress(allocator, elf_path)) |symbol_addr| {
                var rtt_setup_arg =
                    try fmt.allocPrint(
                    allocator,
                    "rtt setup 0x{x} 0x30 \"_SEGGER_RTT\"",
                    .{symbol_addr},
                );

                try args.appendSlice(&[_]DynStr{
                    DynStr{ .static = "-c" },
                    DynStr{ .dynamic = rtt_setup_arg },
                    DynStr{ .static = "-c" },
                    DynStr{ .static = "rtt start" },
                });
            } else {
                var std_err = io.getStdErr().writer();
                unwrap(
                    void,
                    std_err.writeAll("warning: no rtt control block found\n"),
                );
            }
        }

        return .{ .allocator = allocator, .args = args };
    }

    fn toStrs(
        self: *const OpenocdArgs,
        allocator: Allocator,
    ) !ArrayList([]const u8) {
        var args = ArrayList([]const u8).init(allocator);

        for (self.args.items) |arg| {
            switch (arg) {
                .static => |str| try args.append(str),
                .dynamic => |str| try args.append(str),
            }
        }

        return args;
    }

    fn deinit(self: *OpenocdArgs) void {
        for (self.args.items) |arg| {
            switch (arg) {
                .dynamic => |str| self.allocator.free(str),
                else => {},
            }
        }
        self.args.deinit();
    }
};

/// Wraps an OpenOCD child process providing line-by-line output iteration.
const OpenocdReader = struct {
    allocator: Allocator,
    child: std.ChildProcess,
    line_buf: ArrayList([]const u8),
    pos: usize,
    keep_going: bool,

    /// Initializes the reader (first arg should be `openocd` itself).
    fn init(allocator: Allocator, args: *const OpenocdArgs) !OpenocdReader {
        var arg_strs = try args.toStrs(allocator);
        defer arg_strs.deinit();

        var child = process.Child.init(arg_strs.items, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();

        var line_buf = ArrayList([]const u8).init(allocator);

        return OpenocdReader{
            .allocator = allocator,
            .child = child,
            .line_buf = line_buf,
            .pos = 0,
            .keep_going = true,
        };
    }

    /// Wait for the next line of output.
    ///
    /// Returns `null` once the child process has exited.
    fn next(self: *OpenocdReader) !?[]const u8 {
        if (self.pos < self.line_buf.items.len) {
            const line = self.line_buf.items[self.pos];
            self.pos += 1;
            return line;
        } else if (!self.keep_going) {
            return null;
        }

        var poller = io.poll(self.allocator, enum { stdout, stderr }, .{
            .stdout = self.child.stdout.?,
            .stderr = self.child.stderr.?,
        });
        defer poller.deinit();

        if (self.keep_going) {
            self.keep_going = try poller.poll();
            const fifo = poller.fifo(.stderr);
            const stderr = fifo.buf[0..fifo.count];
            var stderr_lines = mem.split(u8, stderr, "\n");
            while (stderr_lines.next()) |line| {
                try self.line_buf.append(try self.allocator.dupe(u8, line));
            }
        }

        return self.next();
    }

    /// Deallocate managed resources.
    fn deinit(self: *OpenocdReader) void {
        for (self.line_buf.items) |line| {
            self.allocator.free(line);
        }
        self.line_buf.deinit();
    }
};

/// Tries to find the address of `_SEGGER_RTT` in a firmware ELF image.
fn findRttSymbolAddress(allocator: Allocator, elf: []const u8) !?usize {
    var exec_result = try process.Child.exec(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "nm", elf },
    });

    switch (exec_result.term) {
        .Exited => |exit_code| if (exit_code != 0) return error.NmExecFailed,
        else => return error.NmExecFailed,
    }

    var lines = mem.split(u8, exec_result.stdout, "\n");

    while (lines.next()) |line| {
        if (line.len == 0) {
            break;
        }

        var items = mem.split(u8, line, " ");

        const addr = items.next() orelse return error.ParseNmOutput;
        _ = items.next();
        const symbol = items.next() orelse return error.ParseNmOutput;

        if (mem.eql(u8, symbol, "_SEGGER_RTT")) {
            return try fmt.parseInt(usize, addr, 16);
        }
    }

    return null;
}

/// Unwraps a fallible type, panicking if it is an error.
fn unwrap(comptime T: type, value: anyerror!T) T {
    return value catch @panic("unwrap failed");
}

/// Pops an argument from the arg iterator.
///
/// If an argument is not present prints the usage text and exits with code 64.
fn popArg(iter: *process.ArgIterator) []const u8 {
    return iter.next() orelse exitUsage();
}

/// Prints the usage text for the runner.
fn printUsage() !void {
    var std_err = io.getStdErr().writer();
    try std_err.writeAll(
        \\usage: zig build xrun -- [<cmd>]
        \\
    );
}

/// Prints the help text for the runner.
fn printHelp() !void {
    var std_out = io.getStdOut().writer();
    try std_out.writeAll(
        \\usage: zig build xrun -- [<cmd>]
        \\
        \\Arguments:
        \\
        \\    cmd: Command to execute [default=`monitor`].   
        \\
        \\Commands:
        \\
        \\    flash:   Flash the firmware and exit.
        \\    gdb:     Flash the firmware and start an interactive GDB session. 
        \\    monitor: Flash the firmware and monitor for RTT messages.
        \\
    );
}

/// Prints an error.
fn printError(allocator: Allocator, err: anyerror) !void {
    var std_err = io.getStdErr().writer();
    var err_str = try fmt.allocPrint(allocator, "{}", .{err});
    defer allocator.free(err_str);
    try std_err.print("error: {s}\n", .{err_str[6..]});
}

/// Prints usage text then exits with code 64.
fn exitUsage() noreturn {
    unwrap(void, printUsage());
    process.exit(64);
}
