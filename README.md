# CBOR Credential Database Format

This document describes a format to store secrets at rest based on the CBOR data format. It is designed as an alternative to other file formats like KDBX used with KeePass and KeePassXC.

## Source Code

### Installation

Versions:

| Zig version | ccdb version |
|:-----------:|:------------:|
| 0.13.0      | 0.1.0, 0.2.0 |
| 0.14.0      | 0.3.0 |

#### Module

The `ccdb` module can be added to your projects by adding `ccdb` to your list of dependencies in `build.zig.zon`.

```zig
.dependencies = .{
    //...
    .ccdb = .{
        .url = "https://github.com/r4gus/ccdb/archive/refs/tags/0.1.0.tar.gz",
        // Adjust the hash if you use another version!
        .hash = "12202413b8cfe91ea51f3680b8eaa5645870a6e3fabc5cb9076c80f8182ea1d4028f",
    },
},
```

Alternatively you can use the following command, which will automatically add `ccdb` as an dependency to your `build.zig.zon` file:

```bash
# Replace <VERSION TAG> with the version you want to use
zig fetch --save https://github.com/r4gus/ccdb/archive/refs/tags/<VERSION TAG>.tar.gz
``` 

You can then import the module within your `build.zig`.

```zig
const ccdb_dep = b.dependency("ccdb", .{
    .target = target,
    .optimize = optimize,
});

// Create a exe or library and then...
exe.root_module.addImport("ccdb", ccdb_dep.module("ccdb"));
```

#### Command Line Tool

You can manage a CCDB database from the command line using `ccdbcmd`. Run `build zig -Doptimize=ReleaseSmall`
to build the executable.

## Documentation

You can build the documentation by running `bikeshed` within the `/docs` folder.
