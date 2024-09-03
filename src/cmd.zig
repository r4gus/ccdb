const std = @import("std");
const clap = @import("clap");
const ccdb = @import("ccdb");
const cbor = @import("zbor");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const help =
    \\usage: ccdbcmd <option(s)>
    \\ Display and modify the content of a CCDB credential database.
    \\ Options are:
    \\  -h, --help                                  Display this help and exit.
    \\  -l, --list                                  List all credentials.
    \\  -o, --open <str>                            Open database file.
    \\  -p, --password <str>                        A password. This should be entered using command line substituation!
    \\  -i, --index <int>                           Index of an entry.
    \\  -e, --export [JSON, CBOR]                   Export an entry using the specified file format.
    \\  -c, --change                                Change password.
    \\  -n, --new                Create a new entry.
    \\  --name <str>             Specify the name for an entry.
    \\  --notes <str>            Specify the notes for an entry.
    \\  --secret                 Specify the secret for an entry over stdin.
    \\  --url <str>              Specify the URL for an entry.
    \\
    \\ Security considerations:
    \\  The password file should only be readable by the user. Please do not enter your password
    \\  on the command line as other users might be able to read it.
    \\
    \\ Examples:
    \\  `ccdbcmd -o ~/.passkeez/db.ccdb -p $(cat pw.txt) -i 0 -e CBOR`        Export the given entry as CBOR
    \\
;

pub fn main() !void {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();
    const stderr = std.io.getStdErr();
    // ---------------------------------------------------
    // Command Line Argument Parsing
    // ---------------------------------------------------
    var password: ?[]const u8 = null;
    defer if (password) |pw| allocator.free(pw);

    const params = comptime clap.parseParamsComptime(
        \\-h, --help               Display this help and exit.
        \\-l, --list               List all credentials.
        \\-o, --open <str>         Open database file.
        \\-p, --password <str>     A password. This should be entered using command line substituation!
        \\-i, --index <usize>      Index of an entry.
        \\-e, --export <str>       Export an entry using the specified file format.
        \\-c, --change             Change password.
        \\-n, --new                Create a new entry.
        \\--name <str>             Specify the name for an entry.
        \\--notes <str>            Specify the notes for an entry.
        \\--secret                 Specify the secret for an entry over stdin.
        \\--url <str>              Specify the URL for an entry.
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
        try std.fmt.format(stdout.writer(), help, .{});
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
            if (res.args.index) |i| {
                if (database.body.entries.items.len <= i) {
                    try std.fmt.format(stderr.writer(), "index out of bounds\n", .{});
                    return;
                }
                const entry = database.body.entries.items[i];

                if (std.mem.eql(u8, "JSON", e) or std.mem.eql(u8, "json", e)) {
                    try serializeEntryToJson(&entry, stdout);
                } else if (std.mem.eql(u8, "CBOR", e) or std.mem.eql(u8, "cbor", e)) {
                    var arr = std.ArrayList(u8).init(allocator);
                    defer arr.deinit();

                    try cbor.stringify(entry, .{}, arr.writer());
                    try std.fmt.format(stdout.writer(), "{s}\n", .{std.fmt.fmtSliceHexLower(arr.items)});
                } else {
                    try std.fmt.format(stderr.writer(), "unsupported file format '{s}'\n", .{e});
                    return;
                }
            } else {
                try std.fmt.format(stderr.writer(), "operation requires index or uuid\n", .{});
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
            var e = database.body.newEntry() catch {
                try std.fmt.format(stderr.writer(), "unable to create new entry\n", .{});
                return;
            };

            if (res.args.name) |v| {
                try e.setName(v);
            }

            if (res.args.notes) |v| {
                try e.setNotes(v);
            }

            if (res.args.secret != 0) {
                try std.fmt.format(stdout.writer(), "secret: ", .{});
                const s = try stdin.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', 256);
                defer if (s) |s_| allocator.free(s_);
                try e.setSecret(s.?);
            }

            if (res.args.url) |v| {
                try e.setUrl(v);
            }

            try writeDb(allocator, file, &database);
        }

        return;
    }
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
