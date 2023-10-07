# _xrun.zig_

An OpenOCD wrapper to run Zig firmware directly from your `build.zig`.

Dual licensed under the 0BSD and MIT licenses.

## In action

Using `xrun` as a run step in your Zig build will first flash your firmware
onto target hardware, then monitor the running firmware for RTT output:

![demo_gif](./assets/demo.gif)

The runner exits when it encounters a breakpoint.

If we change the breakpoint to a panic, `xrun` will print a backtrace for you:

![demo_panic](./assets/demo_panic.gif)

## Dependencies

Right now it's only possible to use `xrun` on MacOS or Linux.

The `xrun` binary depends on:

  * `openocd`
  * `gdb-multiarch`
  * `nm`

You will need to have all three of these installed.

## Configuration

`xrun` is configured in an `xrun.zig.zon` file at the root of your project.

An example is shown below for the Raspberry Pi Pico H:

```zig
.{
    // REQUIRED

    // The OpenOCD target -- configured as `target/{}.cfg`.
    .target = "rp2040",
    // The OpenOCD interface -- configured as `interface/{}.cfg`.
    .interface = "cmsis-dap",

    // OPTIONAL

    // The adapter speed in kHz.
    .adapter_speed = 5000,
    // Override the GDB binary. If unset, defaults to `gdb-multiarch`.
    .gdb = "arm-none-eabi-gdb",
}
```

## Getting Started

Add `xrun` to your `build.zig.zon` like so:

```zig
.{
    .name = "my-firmware",
    .version = "1.0.0",
    .dependencies = .{
        .xrun = .{
            .url = "https://github.com/rjsberry/xrun.zig/archive/24a7428e6bcdd91d17af631a89f267310c0a8519.tar.gz",
            .hash = "1220d9b2eb5d788c13d57caf2f2284294e1d3fb3fa928859c77813f92b9557690651",
        },
    },
}
```

Use the build wrapper in your `build.zig` to add run artifacts:

```zig
const std = @import("std");

const Xrun = @import("xrun").Xrun;

pub fn build(b: *std.Build) void {
    var xrun = Xrun.init(b);

    // Set up your firmware build
    //
    // The following assumes you have stored the result of `b.addExecutable`
    // in a variable called `exe`

    const xrun_cmd = xrun.addRunArtifact(.{ .exe = exe });

    const xrun_step = b.step("xrun", "Run the firmware on target hardware");
    xrun_step.dependOn(&xrun_cmd.step);
}
```

## Usage

You can view the command line help text with the `-h` or `--help` args:

```
zig build xrun -- --help
usage: zig build xrun -- [<cmd>]

Arguments:

    cmd: Command to execute [default=`monitor`].

Commands:

    flash:   Flash the firmware and exit.
    gdb:     Flash the firmware and start an interactive GDB session.
    monitor: Flash the firmware and monitor for RTT messages.
```

For example, to simply flash the firmware:

```
zig build xrun -- flash
```

To start an interactive GDB session:

```
zig build xrun -- gdb
```
