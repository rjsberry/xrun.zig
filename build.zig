// The contents of this file is dual-licensed under the MIT or 0BSD license.

const std = @import("std");
const builtin = @import("builtin");

const fs = std.fs;
const zig = std.zig;

const Step = std.Build.Step;

pub fn build(b: *std.Build) void {
    _ = b.standardTargetOptions(.{});
    _ = b.standardOptimizeOption(.{});
}

/// The Xrun firmware runner.
pub const Xrun = struct {
    b: *std.Build,
    runner: *Step.Compile,

    /// Initializes the runner.
    pub fn init(b: *std.Build) Xrun {
        const path = comptime blk: {
            const dir = std.fs.path.dirname(@src().file) orelse unreachable;
            break :blk dir ++ "/xrun.zig";
        };

        const runner = b.addExecutable(.{
            .name = "xrun_runner",
            .root_source_file = .{ .path = path },
            .target = zig.CrossTarget.fromTarget(builtin.target),
            .optimize = .Debug,
        });

        return .{ .b = b, .runner = runner };
    }

    /// Creates a step to wrap execution of firmware with the `xrun` runner.
    pub fn addRunArtifact(self: *Xrun, args: struct {
        executable: *Step.Compile,
        forward_args: bool = true,
    }) *Step.Run {
        // If the caller hasn't already added the firmware as an install
        // artifact we need to do that ourselves so we can access the path to
        // the compiled firmware binary to pass to the runner.
        self.b.installArtifact(args.executable);

        var run_cmd = self.b.addRunArtifact(self.runner);

        const cfg_path = self.b.pathFromRoot("xrun.zig.zon");
        run_cmd.addArg(cfg_path);
        const elf_path = self.b.getInstallPath(.bin, args.executable.name);
        run_cmd.addArg(elf_path);

        run_cmd.step.dependOn(self.b.getInstallStep());

        // Allows the user to pass arguments to the runner.
        if (args.forward_args) {
            if (self.b.args) |cli_args| {
                run_cmd.addArgs(cli_args);
            }
        }

        return run_cmd;
    }
};
