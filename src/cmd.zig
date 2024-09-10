const std = @import("std");
const clap = @import("clap");
const ccdb = @import("ccdb");
const cbor = @import("zbor");
const builtin = @import("builtin");

const VERSION = "0.1.0";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const help =
    \\ccdb {s}
    \\Copyright (C) 2024 David P. Sugar (r4gus)
    \\License MIT <https://opensource.org/license/MIT>
    \\This is free software: you are free to change and redistribute it.
    \\There is NO WARRANTY, to the extent permitted by law.
    \\
    \\Supported cipher suites:
    \\ CCDB_XCHACHA20_POLY1305_ARGON2ID
    \\
    \\Syntax: ccdb [options]
    \\ Display and modify the content of a CCDB credential database.
    \\
    \\Commands:
    \\ -h, --help                                  Display this help and exit.
    \\ -l, --list                                  List all credentials.
    \\ --export [JSON, CBOR]                       Export an entry using the specified file format.
    \\ -c, --change                                Change password.
    \\ -n, --new                                   Create a new entry.
    \\ --get-secret                                Return the secret of an entry.
    \\ -d, --delete                                Delete database entry.
    \\ --edit                                      Edit a database entry.
    \\
    \\Options controlling the input:
    \\ -o, --open <str>                            Open database file.
    \\ -p, --password <str>                        A password. This should be entered using command line substituation!
    \\ --name <str>                                Specify the name for an entry.
    \\ --notes <str>                               Specify the notes for an entry.
    \\ --secret                                    Specify the secret for an entry over stdin.
    \\ --url <str>                                 Specify the URL for an entry.
    \\
    \\Options controlling the credential selection:
    \\ -i, --index <int>                           Index of an entry.
    \\ --uuid <str>                                Specify a uuid of an entry.
    \\
    \\Security considerations:
    \\  The password file should only be readable by the user. Please do not enter your password
    \\  on the command line as other users might be able to read it.
    \\
    \\Examples:
    \\ Export the first entry as CBOR
    \\  -o ~/.passkeez/db.ccdb -p $(cat pw.txt) -i 0 -e CBOR     
    \\ Create a new entry for Github
    \\  -o ~/Documents/db.ccdb -n --name "Github" --notes "My dev account" --secret --url "https://github.com"   
    \\
;

pub fn main() !void {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();
    const stderr = std.io.getStdErr();

    //if (builtin.target.isGnuLibC()) {
    //    std.log.info("locking memory...", .{});
    //    const mman = @cImport({
    //        @cInclude("sys/mman.h");
    //    });

    //    if (mman.mlockall(mman.MCL_CURRENT | mman.MCL_FUTURE) != 0) {
    //        try std.fmt.format(stderr.writer(), "unable to lock pages\n", .{});
    //        return;
    //    }
    //}

    // ---------------------------------------------------
    // Command Line Argument Parsing
    // ---------------------------------------------------
    var password: ?[]u8 = null;
    defer if (password) |pw| {
        @memset(pw, 0);
        allocator.free(pw);
    };

    const params = comptime clap.parseParamsComptime(
        \\-h, --help               Display this help and exit.
        \\-l, --list               List all credentials.
        \\-o, --open <str>         Open database file.
        \\-p, --password <str>     A password. This should be entered using command line substituation!
        \\-i, --index <usize>      Index of an entry.
        \\--uuid <str>             Specify a uuid of an entry.
        \\--export <str>           Export an entry using the specified file format.
        \\-c, --change             Change password.
        \\-n, --new                Create a new entry.
        \\--name <str>             Specify the name for an entry.
        \\--notes <str>            Specify the notes for an entry.
        \\--secret                 Specify the secret for an entry over stdin.
        \\--url <str>              Specify the URL for an entry.
        \\--get-secret             Return the secret of an entry.
        \\-d, --delete             Delete database entry.
        \\--edit                   Edit a database entry.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = gpa.allocator(),
    }) catch |err| {
        // Report useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try std.fmt.format(stdout.writer(), help, .{VERSION});
        return;
    }
    if (res.args.password) |p| {
        password = try allocator.dupe(u8, p);
    }

    // ---------------------------------------------------
    // Load Database
    // ---------------------------------------------------
    if (res.args.open) |file| {
        if (password == null) {
            try std.fmt.format(stdout.writer(), "password: ", .{});
            password = try stdin.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', 256);
        }

        var database = open(file, password.?, allocator) catch |e| {
            try std.fmt.format(stderr.writer(), "unable to open {s} ({any})\n", .{ file, e });
            return;
        };
        defer database.deinit();

        if (res.args.list != 0) {
            for (database.body.entries.items, 0..) |entry, i| {
                try std.fmt.format(stdout.writer(), "[{d}] {s}\n", .{ i, entry.uuid });
                if (entry.name) |name| {
                    try std.fmt.format(stdout.writer(), "  name: {s}\n", .{name});
                }
                if (entry.url) |url| {
                    try std.fmt.format(stdout.writer(), "  url: {s}\n", .{url});
                }
                if (entry.user) |user| {
                    if (user.display_name) |dn| {
                        try std.fmt.format(stdout.writer(), "  user: {s}\n", .{dn});
                    } else if (user.name) |n| {
                        try std.fmt.format(stdout.writer(), "  user: {s}\n", .{n});
                    }
                }
            }
        } else if (res.args.@"export") |e| {
            const entry = getEntry(res, &database, stderr) catch {
                return;
            };

            if (std.mem.eql(u8, "JSON", e) or std.mem.eql(u8, "json", e)) {
                try serializeEntryToJson(entry, stdout);
            } else if (std.mem.eql(u8, "CBOR", e) or std.mem.eql(u8, "cbor", e)) {
                var arr = std.ArrayList(u8).init(allocator);
                defer arr.deinit();

                try cbor.stringify(entry, .{}, arr.writer());
                try std.fmt.format(stdout.writer(), "{s}\n", .{std.fmt.fmtSliceHexLower(arr.items)});
            } else {
                try std.fmt.format(stderr.writer(), "unsupported file format '{s}'\n", .{e});
                return;
            }
        } else if (res.args.change != 0) {
            try std.fmt.format(stdout.writer(), "new password: ", .{});
            const new_password = try stdin.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', 256);
            if (new_password == null) {
                try std.fmt.format(stderr.writer(), "no password entered\n", .{});
                return;
            }

            try database.setKey(new_password.?);

            try writeDb(allocator, file, &database);
        } else if (res.args.new != 0) {
            const e = database.body.newEntry() catch {
                try std.fmt.format(stderr.writer(), "unable to create new entry\n", .{});
                return;
            };
            try editEntry(res, e, stdout, stdin);
            try writeDb(allocator, file, &database);
        } else if (res.args.edit != 0) {
            const e = getEntry(res, &database, stderr) catch {
                return;
            };
            try editEntry(res, e, stdout, stdin);
            try writeDb(allocator, file, &database);
        } else if (res.args.@"get-secret" != 0) {
            const entry = getEntry(res, &database, stderr) catch {
                return;
            };

            if (entry.secret) |secret| {
                try std.fmt.format(stdout.writer(), "{s}\n", .{secret});
            } else {
                try std.fmt.format(stdout.writer(), "", .{});
            }
        } else if (res.args.delete != 0) {
            const entry = try getEntry(res, &database, stderr);
            // Do NOT touch entry after this!!! `entry` is a dangling pointer!
            database.body.deleteEntryById(entry.uuid) catch |e| {
                try std.fmt.format(stderr.writer(), "unable to delete entry ({any})\n", .{e});
                return;
            };

            try writeDb(allocator, file, &database);
        }

        return;
    }
}

fn editEntry(res: anytype, e: *ccdb.Entry, stdout: std.fs.File, stdin: std.fs.File) !void {
    if (res.args.name) |v| {
        try e.setName(v);
    }

    if (res.args.notes) |v| {
        try e.setNotes(v);
    }

    if (res.args.secret != 0) {
        try std.fmt.format(stdout.writer(), "secret: ", .{});
        const s = try stdin.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', 256);
        defer if (s) |s_| {
            @memset(s_, 0);
            allocator.free(s_);
        };
        try e.setSecret(s.?);
    }

    if (res.args.url) |v| {
        try e.setUrl(v);
    }
}

fn getEntry(res: anytype, database: *ccdb.Db, stderr: std.fs.File) !*ccdb.Entry {
    return if (res.args.index) |i| blk: {
        if (database.body.entries.items.len <= i) {
            try std.fmt.format(stderr.writer(), "index out of bounds\n", .{});
            return error.NoEntry;
        }
        break :blk &database.body.entries.items[i];
    } else if (res.args.uuid) |uuid| blk: {
        const entry = database.body.getEntryById(uuid);
        if (entry == null) {
            try std.fmt.format(stderr.writer(), "no entry with uuid {s}\n", .{uuid});
            return error.NoEntry;
        }

        break :blk entry.?;
    } else {
        try std.fmt.format(stderr.writer(), "operation requires index or uuid\n", .{});
        return error.NoEntry;
    };
}

const Entry = struct {
    name: ?[]const u8 = null,
    notes: ?[]const u8 = null,
    secret: ?[]const u8 = null,
    key: ?cbor.cose.Key = null,
    url: ?[]const u8 = null,
    user: ?ccdb.User = null,
    tags: ?[]const []const u8 = null,
    attach: ?[]const ccdb.Attachment = null,
};

fn serializeEntryToJson(entry: *const ccdb.Entry, stdout: anytype) !void {
    try stdout.writer().writeAll("{\n");
    try std.fmt.format(stdout.writer(), "    \"uuid\": \"{s}\"", .{entry.uuid});
    if (entry.name) |v| try std.fmt.format(stdout.writer(), ",\n    \"name\": \"{s}\"", .{v});
    {
        try stdout.writer().writeAll(",\n    \"times\": {\n");
        try std.fmt.format(stdout.writer(), "        \"creat\": {d},\n", .{entry.times.creat});
        try std.fmt.format(stdout.writer(), "        \"mod\": {d}", .{entry.times.mod});
        if (entry.times.exp) |exp| try std.fmt.format(stdout.writer(), ",\n        \"exp\": {d}", .{exp});
        if (entry.times.cnt) |cnt| try std.fmt.format(stdout.writer(), ",\n        \"cnt\": {d}", .{cnt});
        try stdout.writer().writeAll("\n    }");
    }
    if (entry.notes) |v| try std.fmt.format(stdout.writer(), ",\n    \"notes\": \"{s}\"", .{v});
    if (entry.secret) |v| try std.fmt.format(stdout.writer(), ",\n    \"secret\": \"{s}\"", .{std.fmt.fmtSliceHexLower(v)});
    if (entry.key) |v| {
        try std.fmt.format(stdout.writer(), ",\n    \"key\": ", .{});
        try std.json.stringify(v, .{}, stdout.writer());
    }
    if (entry.url) |v| try std.fmt.format(stdout.writer(), ",\n    \"url\": \"{s}\"", .{v});
    if (entry.user) |user| {
        try stdout.writer().writeAll(",\n    \"user\": {\n");
        if (user.id) |id| try std.fmt.format(stdout.writer(), "        \"id\": \"{s}\"", .{std.fmt.fmtSliceHexLower(id)});
        if (user.name) |name| try std.fmt.format(stdout.writer(), ",\n        \"name\": \"{s}\"", .{name});
        if (user.display_name) |name| try std.fmt.format(stdout.writer(), ",\n        \"display_name\": \"{s}\"", .{name});
        try stdout.writer().writeAll("\n    }");
    }
    // We'll ignore any relationships
    //if (entry.group) |v| try std.fmt.format(stdout.writer(), ",\n    \"group\": \"{s}\"", .{v});
    if (entry.tags) |v| {
        try std.fmt.format(stdout.writer(), ",\n    \"tags\": [", .{});
        for (v, 0..) |t, j| {
            if (j > 0) try stdout.writer().writeAll(",");
            try std.fmt.format(stdout.writer(), "\n        \"{s}\"", .{t});
        }
        try stdout.writer().writeAll("\n    ]");
    }
    if (entry.attach) |v| {
        try std.fmt.format(stdout.writer(), ",\n    \"attach\": [", .{});
        for (v, 0..) |attachment, j| {
            if (j > 0) try stdout.writer().writeAll(",");
            try stdout.writer().writeAll("\n            {\n");
            try std.fmt.format(stdout.writer(), "            \"desc\" \"{s}\",\n", .{attachment.desc});
            try std.fmt.format(stdout.writer(), "            \"att\" \"{s}\"\n", .{std.fmt.fmtSliceHexLower(attachment.att)});
            try stdout.writer().writeAll("        }");
        }
        try stdout.writer().writeAll("\n    ]");
    }
    try stdout.writer().writeAll("\n}\n");
}

pub fn open2(path: []const u8) !std.fs.File {
    return try std.fs.openFileAbsolute(path[0..], .{
        .mode = .read_write,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });
}

pub fn open(path: []const u8, pw: []const u8, a: std.mem.Allocator) !ccdb.Db {
    const file = try open2(path);
    defer file.close();

    const mem = try file.readToEndAlloc(a, 50_000_000);
    defer a.free(mem);

    return ccdb.Db.open(
        mem,
        a,
        std.time.milliTimestamp,
        std.crypto.random,
        pw,
    );
}

pub fn writeDb(a: std.mem.Allocator, path: []const u8, database: *ccdb.Db) !void {
    var f2 = std.fs.createFileAbsolute("/tmp/db.trs", .{ .truncate = true }) catch |e| {
        std.log.err("unable to open temporary file in /tmp", .{});
        return e;
    };
    defer f2.close();

    const raw = database.seal(a) catch |e| {
        std.log.err("unable to seal database ({any})", .{e});
        return e;
    };
    defer {
        @memset(raw, 0);
        a.free(raw);
    }

    f2.writer().writeAll(raw) catch |e| {
        std.log.err("unable to persist database ({any})", .{e});
        return e;
    };

    std.fs.copyFileAbsolute("/tmp/db.trs", path, .{}) catch |e| {
        std.log.err("unable to overwrite file `{s}`", .{path});
        return e;
    };
}
