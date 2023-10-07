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

