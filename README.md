This project is still WIP.

# Xojo CLI Tools

Collection of command-line utilities for Xojo developers.

You may also be interested in [xojo-docker](https://github.com/kmaehashi/xojo-docker).

## Installation

```sh
pip install git+https://github.com/kmaehashi/xojo-tools.git
```

## Commands

### xojo-ide-communicator

Python version of the [IDE Communicator](https://docs.xojo.com/UserGuide:IDE_Communicator).
This reimplementation has some benefits over the official Xojo version especially in automated systems like continuous integration (CI):

* Easy to deploy -- single-file, lightweight, pure Python script with no dependencies
* Handy -- submit commands without creating a temporary file (`--command` option)
* Reliable -- provides options for automated systems, e.g., to wait until the IDE is ready to accept commands (`--wait` option) or terminate if the process took longer than expected (`--timeout` option)
* Free -- no Xojo license required (Xojo version requires Desktop or Console license to build)

Usage:

```sh
$ xojo-ide-communicator --help
```

Example:

TODO

Hints:

* Protocol version 1 only supports one-way communication (`--receive` option cannot be specified).
* Protocol version 2 (implemented in Xojo VERSION TODO or later) supports two-way communication, but be aware that messages sent and received are not one-to-one mapping.
    * Nothing will be returned by default. You must produce an output using `Print()` in your script; response will be given for each `Print()` call. (TODO is this correct?)
    * If you directly interact with the IDE GUI (e.g., manually open a project), responses will be sent without any messages.
* See [Environment Variables](https://docs.xojo.com/UserGuide:IDE_Communicator#Environment_Variables) for handy environment variables for automated systems.

TODO support disabling timeout

### xojo-quote

Quotes a string into Xojo string.
Convenient when constructing an IDE script from a shell script.

Example:

```sh
$ cat input
Hello
World

$ echo "Print( $(xojo-quote -f input) )" > script

$ cat script
Print("Hello" + EndOfLine + "World")
```

### xojo-accept-eula

Skip EULA agreement dialog to run the IDE in headless mode.

By using this tool, you are considered that you agreed with the Xojo license.
Please use at your own risk.

Usage:

```sh
$ xojo-accept-eula
```
