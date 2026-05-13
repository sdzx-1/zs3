const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const acl = @import("acl.zig");
const tracy = @import("tracy.zig");
const trace = tracy.trace;

const MAX_HEADER_SIZE = 8 * 1024;
const MAX_BODY_SIZE = 5 * 1024 * 1024 * 1024;
const MAX_KEY_LENGTH = 1024;
const MAX_BUCKET_LENGTH = 63;
const MAX_CONNECTIONS = 1024;

const ERROR_403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nDenied";

/// Format a Unix timestamp (seconds) as an HTTP date (RFC 7231).
/// Returns a 29-byte string like "Mon, 02 Jan 2006 15:04:05 GMT".
/// When using with Response.setHeader, the returned slice must outlive
/// the response — use allocHttpDate to get a heap-allocated copy.
pub fn formatHttpDate(buf: *[29]u8, timestamp: i64) void {
    const secs: u64 = if (timestamp > 0) @intCast(timestamp) else 0;
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    const dow = @mod(@as(i32, @intCast(day.day)) + 4, 7); // epoch was Thursday=4
    const day_names = [7]*const [3]u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const month_names = [12]*const [3]u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const mon_idx = @intFromEnum(md.month) - 1;

    _ = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[@intCast(dow)],
        md.day_index + 1,
        month_names[mon_idx],
        yd.year,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// Format a Unix timestamp (seconds) as ISO 8601 for S3 XML responses.
/// Returns a 20-byte string like "2006-01-02T15:04:05Z".
pub fn formatIso8601(buf: *[20]u8, timestamp: i64) void {
    const secs: u64 = if (timestamp > 0) @intCast(timestamp) else 0;
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    _ = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @intFromEnum(md.month),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// Decode AWS chunked transfer encoding.
/// Format: <hex-size>;chunk-signature=...\r\n<data>\r\n repeated, terminated by 0-size chunk.
pub fn decodeAwsChunked(allocator: Allocator, body: []const u8) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var pos: usize = 0;
    while (pos < body.len) {
        // Find the end of the chunk header line (terminated by \r\n)
        const line_end = std.mem.indexOfPos(u8, body, pos, "\r\n") orelse break;
        const chunk_header = body[pos..line_end];

        // Parse hex chunk size (before the first ';')
        const size_end = std.mem.indexOf(u8, chunk_header, ";") orelse chunk_header.len;
        const hex_str = chunk_header[0..size_end];
        const chunk_size = std.fmt.parseInt(usize, hex_str, 16) catch break;

        if (chunk_size == 0) break;

        // Data starts after \r\n
        const data_start = line_end + 2;
        if (data_start + chunk_size > body.len) break;

        try result.appendSlice(allocator, body[data_start .. data_start + chunk_size]);

        // Skip past data + \r\n
        pos = data_start + chunk_size + 2;
    }

    return result.toOwnedSlice(allocator);
}

/// Heap-allocate an RFC 7231 date string suitable for Response.setHeader.
fn allocHttpDate(allocator: Allocator, timestamp: i64) ![]const u8 {
    var buf: [29]u8 = undefined;
    formatHttpDate(&buf, timestamp);
    return allocator.dupe(u8, &buf);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse CLI arguments
    var port: u16 = 9000;
    var data_dir: []const u8 = build_options.data_dir;
    var raw_acl_list: []const u8 = build_options.acl_list;
    var show_help: bool = false;

    var args = std.process.args();
    _ = args.skip(); // Skip program name
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--data-dir=")) {
            data_dir = arg[11..];
        } else if (std.mem.startsWith(u8, arg, "--acl=")) {
            raw_acl_list = arg[6..];
        } else if (std.mem.startsWith(u8, arg, "--port=")) {
            port = std.fmt.parseInt(u16, arg[7..], 10) catch 9000;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            show_help = true;
        }
    }

    if (show_help) {
        std.debug.print(
            \\s3 compatible storage
            \\
            \\Usage: s3 [OPTIONS]
            \\
            \\Options:
            \\  --port={d}
            \\      HTTP port to listen on
            \\
            \\  --data-dir={s}
            \\      The directory to store bucket data under
            \\
            \\  --acl={s}
            \\      The credentials for access
            \\
            \\  --help, -h
            \\      Show this help
            \\
        , .{ port, data_dir, raw_acl_list });
        return;
    }

    const access_control_list = acl.parseCredentials(allocator, raw_acl_list) catch |err| {
        std.log.err("Invalid --acl / -Dacl-list value: {s}", .{@errorName(err)});
        return err;
    };
    defer allocator.free(access_control_list);

    if (std.mem.eql(u8, raw_acl_list, "admin:minioadmin:minioadmin")) {
        std.log.warn("Using built-in default credentials (admin:minioadmin:minioadmin) — DO NOT USE IN PRODUCTION", .{});
    }

    std.fs.cwd().makeDir(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Keys reference slices in raw_acl_list (argv or build_options string), both of
    // which outlive the process — safe to store as map keys without copying.
    var access_control_map = std.StringHashMap(acl.Credential).init(allocator);
    errdefer access_control_map.deinit();

    for (access_control_list) |credential| {
        const gop = try access_control_map.getOrPut(credential.access_key);
        if (gop.found_existing) {
            std.log.err("Duplicate access key '{s}' in ACL list", .{credential.access_key});
            return error.DuplicateAccessKey;
        }
        gop.value_ptr.* = credential;
    }

    var ctx = S3Context{
        .allocator = allocator,
        .data_dir = data_dir,
        .access_control_map = access_control_map,
    };
    defer ctx.deinit();

    const address = net.Address.parseIp4("0.0.0.0", port) catch unreachable;
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.log.info("S3 server listening on http://0.0.0.0:{d}", .{port});

    if (tracy.enable_allocation) {
        var gpa_tracy = tracy.tracyAllocator(allocator);
        try eventLoopEpoll(gpa_tracy.allocator(), &ctx, &server);
    } else {
        try eventLoopEpoll(allocator, &ctx, &server);
    }
}

fn setNonBlocking(fd: posix.fd_t) void {
    const O_NONBLOCK: usize = 0x800;
    const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    _ = posix.fcntl(fd, posix.F.SETFL, flags | O_NONBLOCK) catch {};
}

fn eventLoopEpoll(allocator: Allocator, ctx: *const S3Context, server: *net.Server) !void {
    const linux = std.os.linux;
    const epfd = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (@as(isize, @bitCast(epfd)) < 0) return error.EpollCreate;
    defer _ = linux.close(@intCast(epfd));

    setNonBlocking(server.stream.handle);
    var ev = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .fd = server.stream.handle } };
    if (@as(isize, @bitCast(linux.epoll_ctl(@intCast(epfd), linux.EPOLL.CTL_ADD, server.stream.handle, &ev))) < 0)
        return error.EpollCtl;

    var events: [MAX_CONNECTIONS]linux.epoll_event = undefined;

    while (true) {
        const n = linux.epoll_wait(@intCast(epfd), &events, MAX_CONNECTIONS, -1);
        if (@as(isize, @bitCast(n)) < 0) continue;

        for (events[0..n]) |event| {
            if (event.data.fd == server.stream.handle) {
                while (true) {
                    const conn = server.accept() catch break;
                    var cev = linux.epoll_event{ .events = linux.EPOLL.IN | linux.EPOLL.ONESHOT, .data = .{ .fd = conn.stream.handle } };
                    _ = linux.epoll_ctl(@intCast(epfd), linux.EPOLL.CTL_ADD, conn.stream.handle, &cev);
                }
            } else {
                const stream = net.Stream{ .handle = event.data.fd };
                _ = handleConnectionWithStream(allocator, ctx, stream) catch {};
                _ = linux.epoll_ctl(@intCast(epfd), linux.EPOLL.CTL_DEL, event.data.fd, null);
                stream.close();
            }
        }
    }
}

const S3Context = struct {
    allocator: Allocator,
    data_dir: []const u8,
    access_control_map: std.StringHashMap(acl.Credential),

    fn bucketPath(self: *const S3Context, allocator: Allocator, bucket: []const u8) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.data_dir, bucket });
    }

    fn objectPath(self: *const S3Context, allocator: Allocator, bucket: []const u8, key: []const u8) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.data_dir, bucket, key });
    }

    pub fn deinit(self: *S3Context) void {
        self.access_control_map.deinit();
    }
};

const Request = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,

    fn header(self: *const Request, name: []const u8) ?[]const u8 {
        var lower_buf: [128]u8 = undefined;
        const lower_name = std.ascii.lowerString(&lower_buf, name);
        return self.headers.get(lower_name);
    }

    fn deinit(self: *Request) void {
        self.headers.deinit();
    }
};

const Response = struct {
    status: u16 = 200,
    status_text: []const u8 = "OK",
    headers: std.ArrayListUnmanaged(Header) = .empty,
    body: []const u8 = "",
    send_file: ?std.fs.File = null,
    send_file_size: usize = 0,
    send_file_offset: usize = 0,
    allocator: Allocator,

    const Header = struct { name: []const u8, value: []const u8 };

    fn init(allocator: Allocator) Response {
        return .{
            .allocator = allocator,
        };
    }

    fn deinit(self: *Response) void {
        self.headers.deinit(self.allocator);
        if (self.send_file) |f| f.close();
    }

    fn setHeader(self: *Response, name: []const u8, value: []const u8) void {
        self.headers.append(self.allocator, .{ .name = name, .value = value }) catch {};
    }

    fn ok(self: *Response) void {
        self.status = 200;
        self.status_text = "OK";
    }

    fn noContent(self: *Response) void {
        self.status = 204;
        self.status_text = "No Content";
    }

    fn setXmlBody(self: *Response, body: []const u8) void {
        self.setHeader("Content-Type", "application/xml");
        self.body = body;
    }

    fn setSendFile(self: *Response, file: std.fs.File, size: usize, offset: usize) void {
        self.send_file = file;
        self.send_file_size = size;
        self.send_file_offset = offset;
    }

    fn write(self: *Response, stream: net.Stream) !void {
        const tracy_fun = trace(@src());
        defer tracy_fun.end();

        var buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        try w.print("HTTP/1.1 {d} {s}\r\n", .{ self.status, self.status_text });

        // Check if Content-Length was already set via setHeader
        var has_content_length = false;
        for (self.headers.items) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
                has_content_length = true;
                break;
            }
        }

        // Only add auto Content-Length if not already set
        if (!has_content_length) {
            const content_len = if (self.send_file != null) self.send_file_size else self.body.len;
            try w.print("Content-Length: {d}\r\n", .{content_len});
        }
        try w.writeAll("Connection: close\r\n");

        for (self.headers.items) |h| {
            try w.print("{s}: {s}\r\n", .{ h.name, h.value });
        }
        try w.writeAll("\r\n");

        try stream.writeAll(fbs.getWritten());

        if (self.send_file) |file| {
            // Use sendfile for zero-copy transfer
            var offset: i64 = @intCast(self.send_file_offset);
            var remaining: usize = self.send_file_size;
            while (remaining > 0) {
                const rc = std.os.linux.sendfile(stream.handle, file.handle, &offset, remaining);
                const sent = @as(isize, @bitCast(rc));
                if (sent <= 0) break;
                remaining -= @intCast(sent);
            }
        } else if (self.body.len > 0) {
            // Custom write loop to handle WouldBlock on non-blocking sockets
            var written: usize = 0;
            while (written < self.body.len) {
                const n = posix.write(stream.handle, self.body[written..]) catch |err| switch (err) {
                    error.WouldBlock => {
                        std.Thread.sleep(1_000_000); // 1ms
                        continue;
                    },
                    else => return err,
                };
                if (n == 0) return error.ConnectionResetByPeer;
                written += n;
            }
        }
    }
};

fn parseRequestFromBuf(allocator: Allocator, data: []const u8, stream: net.Stream) !Request {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const total_read = data.len;
    const line_end = std.mem.indexOf(u8, data, "\r\n") orelse return error.InvalidRequest;
    const request_line = data[0..line_end];

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.InvalidRequest;
    const full_path = parts.next() orelse return error.InvalidRequest;
    var path: []const u8 = full_path;
    var query: []const u8 = "";
    if (std.mem.indexOf(u8, full_path, "?")) |q_idx| {
        path = full_path[0..q_idx];
        query = full_path[q_idx + 1 ..];
    }

    var headers = std.StringHashMap([]const u8).init(allocator);
    var header_section = data[line_end + 2 ..];
    const header_end = std.mem.indexOf(u8, header_section, "\r\n\r\n") orelse header_section.len;
    header_section = header_section[0..header_end];

    var header_lines = std.mem.splitSequence(u8, header_section, "\r\n");
    while (header_lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOf(u8, line, ":") orelse continue;
        var name_buf: [128]u8 = undefined;
        const name = std.ascii.lowerString(&name_buf, std.mem.trim(u8, line[0..colon], " "));
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");
        try headers.put(try allocator.dupe(u8, name), try allocator.dupe(u8, value));
    }

    var body: []const u8 = "";
    if (headers.get("content-length")) |cl_str| {
        const content_length = std.fmt.parseInt(usize, cl_str, 10) catch 0;
        if (content_length > MAX_BODY_SIZE) return error.PayloadTooLarge;
        if (content_length > 0) {
            // Handle Expect: 100-continue - send 100 Continue before reading body
            if (headers.get("expect")) |expect| {
                if (std.ascii.eqlIgnoreCase(expect, "100-continue")) {
                    stream.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch {};
                }
            }

            const body_start_idx = std.mem.indexOf(u8, data, "\r\n\r\n").? + 4;
            // Ensure we don't underflow: already_read = max(0, total_read - body_start_idx)
            const already_read = if (total_read > body_start_idx) total_read - body_start_idx else 0;
            // Cap already_read to content_length to prevent overflow in memcpy
            const bytes_to_copy = @min(already_read, content_length);

            const body_buf = try allocator.alloc(u8, content_length);
            if (bytes_to_copy > 0) {
                @memcpy(body_buf[0..bytes_to_copy], data[body_start_idx .. body_start_idx + bytes_to_copy]);
            }

            var remaining = content_length - bytes_to_copy;
            var offset = bytes_to_copy;
            while (remaining > 0) {
                const n = stream.read(body_buf[offset..]) catch |err| {
                    // Handle non-blocking sockets - retry on WouldBlock
                    if (err == error.WouldBlock) {
                        std.Thread.sleep(1_000_000); // 1ms sleep before retry
                        continue;
                    }
                    return err;
                };
                if (n == 0) break;
                offset += n;
                remaining -= n;
            }
            body = body_buf;

            // Decode AWS chunked transfer encoding if present
            if (headers.get("x-amz-content-sha256")) |sha| {
                if (std.mem.eql(u8, sha, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")) {
                    const decoded = try decodeAwsChunked(allocator, body);
                    body = decoded;
                }
            }
        }
    }

    return Request{
        .method = try allocator.dupe(u8, method),
        .path = try allocator.dupe(u8, path),
        .query = try allocator.dupe(u8, query),
        .headers = headers,
        .body = body,
    };
}

fn hasAuth(data: []const u8) bool {
    if (data.len < 14) return false;
    const needle = "authorization:";
    const end = data.len - 13;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        if (std.ascii.toLower(data[i]) == needle[0] and
            std.ascii.toLower(data[i + 1]) == needle[1] and
            std.ascii.toLower(data[i + 2]) == needle[2] and
            std.ascii.toLower(data[i + 3]) == needle[3] and
            std.ascii.toLower(data[i + 4]) == needle[4] and
            std.ascii.toLower(data[i + 5]) == needle[5] and
            std.ascii.toLower(data[i + 6]) == needle[6] and
            std.ascii.toLower(data[i + 7]) == needle[7] and
            std.ascii.toLower(data[i + 8]) == needle[8] and
            std.ascii.toLower(data[i + 9]) == needle[9] and
            std.ascii.toLower(data[i + 10]) == needle[10] and
            std.ascii.toLower(data[i + 11]) == needle[11] and
            std.ascii.toLower(data[i + 12]) == needle[12] and
            data[i + 13] == ':')
        {
            return true;
        }
    }
    return false;
}

fn findHeaderEnd(data: []const u8) ?usize {
    if (data.len < 4) return null;
    const end = data.len - 3;
    const ptr = data.ptr;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        if (ptr[i] == '\r' and ptr[i + 1] == '\n' and ptr[i + 2] == '\r' and ptr[i + 3] == '\n') {
            return i;
        }
    }
    return null;
}

fn handleConnectionWithStream(allocator: Allocator, ctx: *const S3Context, stream: net.Stream) !bool {
    tracy.frameMark();

    var buf: [MAX_HEADER_SIZE]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < buf.len) {
        const n = stream.read(buf[total_read..]) catch return false;
        if (n == 0) return false;
        total_read += n;
        if (findHeaderEnd(buf[0..total_read])) |_| break;
    }
    if (total_read == 0) return false;

    const data = buf[0..total_read];

    if (!hasAuth(data)) {
        _ = stream.write(ERROR_403) catch return false;
        return true;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var req = parseRequestFromBuf(alloc, data, stream) catch return false;
    var res = Response.init(alloc);

    route(ctx, alloc, &req, &res) catch |err| {
        std.log.err("Handler error: {}", .{err});
        sendError(&res, 500, "InternalError", "Internal server error");
    };

    res.write(stream) catch return false;
    return false;
}

pub fn isValidBucketName(name: []const u8) bool {
    if (name.len < 3 or name.len > MAX_BUCKET_LENGTH) return false;
    for (name) |c| {
        // S3 bucket names must be lowercase letters, numbers, hyphens, or dots
        // Uppercase letters are NOT allowed
        if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-' and c != '.') return false;
    }
    if (name[0] == '-' or name[0] == '.' or name[name.len - 1] == '-' or name[name.len - 1] == '.') return false;
    return true;
}

fn isValidUploadId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    }
    return true;
}

pub fn isValidKey(key: []const u8) bool {
    if (key.len == 0 or key.len > MAX_KEY_LENGTH) return false;
    for (key) |c| {
        if (c < 32 or c == 127) return false; // no control chars
    }
    // Block path traversal attempts
    if (std.mem.indexOf(u8, key, "..")) |_| return false;
    // Block absolute paths
    if (key[0] == '/') return false;
    return true;
}

fn route(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    var path = req.path;
    if (path.len > 0 and path[0] == '/') path = path[1..];

    const acl_ctx = SigV4.verify(ctx, req, allocator);

    // S3 API requires authentication
    if (!acl_ctx.authenticated) {
        sendError(res, 403, "AccessDenied", "Invalid credentials");
        return;
    }
    if (!acl_ctx.granted(req.method)) {
        sendError(res, 403, "AccessDenied", "Insufficient permissions");
        return;
    }

    var path_parts = std.mem.splitScalar(u8, path, '/');
    const bucket = path_parts.next() orelse "";
    const key = path_parts.rest();

    if (bucket.len > 0 and !isValidBucketName(bucket)) {
        sendError(res, 400, "InvalidBucketName", "Bucket name is invalid");
        return;
    }
    if (key.len > 0 and !isValidKey(key)) {
        sendError(res, 400, "InvalidKey", "Object key is invalid");
        return;
    }

    // Standard S3 routing (standalone mode or bucket operations)
    if (std.mem.eql(u8, req.method, "GET")) {
        if (bucket.len == 0) {
            try handleListBuckets(ctx, allocator, res);
        } else if (key.len == 0) {
            try handleListObjects(ctx, allocator, req, res, bucket);
        } else {
            try handleGetObject(ctx, allocator, req, res, bucket, key);
        }
    } else if (std.mem.eql(u8, req.method, "PUT")) {
        if (key.len == 0) {
            try handleCreateBucket(ctx, allocator, res, bucket);
        } else if (hasQuery(req.query, "uploadId")) {
            try handleUploadPart(ctx, allocator, req, res, bucket, key);
        } else {
            try handlePutObject(ctx, allocator, req, res, bucket, key);
        }
    } else if (std.mem.eql(u8, req.method, "DELETE")) {
        if (key.len == 0) {
            try handleDeleteBucket(ctx, allocator, res, bucket);
        } else if (hasQuery(req.query, "uploadId")) {
            try handleAbortMultipart(ctx, allocator, req, res);
        } else {
            try handleDeleteObject(ctx, allocator, res, bucket, key);
        }
    } else if (std.mem.eql(u8, req.method, "HEAD")) {
        if (key.len == 0) {
            try handleHeadBucket(ctx, allocator, res, bucket);
        } else {
            try handleHeadObject(ctx, allocator, res, bucket, key);
        }
    } else if (std.mem.eql(u8, req.method, "POST")) {
        if (hasQuery(req.query, "delete")) {
            try handleDeleteObjects(ctx, allocator, req, res, bucket);
        } else if (hasQuery(req.query, "uploads")) {
            try handleInitiateMultipart(ctx, allocator, res, bucket, key);
        } else if (hasQuery(req.query, "uploadId")) {
            try handleCompleteMultipart(ctx, allocator, req, res, bucket, key);
        } else {
            sendError(res, 400, "InvalidRequest", "Unknown POST operation");
        }
    } else {
        sendError(res, 405, "MethodNotAllowed", "Method not allowed");
    }
}

pub const SigV4 = struct {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const Sha256 = std.crypto.hash.sha2.Sha256;

    const ParsedAuth = struct {
        access_key: []const u8,
        date: []const u8,
        region: []const u8,
        service: []const u8,
        signed_headers: []const u8,
        signature: []const u8,
    };

    const ACLCtx = struct {
        authenticated: bool,
        role: ?acl.Role,

        fn granted(self: *const ACLCtx, method: []const u8) bool {
            const role = self.role orelse return false;
            return acl.roleAllowsMethod(role, method);
        }
    };

    fn verify(ctx: *const S3Context, req: *const Request, allocator: Allocator) ACLCtx {
        const tracy_fun = trace(@src());
        defer tracy_fun.end();

        var acl_ctx = ACLCtx{
            .authenticated = false,
            .role = null,
        };

        const auth_header = req.header("authorization") orelse return acl_ctx;
        const x_amz_date = req.header("x-amz-date") orelse return acl_ctx;
        const x_amz_content_sha256 = req.header("x-amz-content-sha256") orelse "UNSIGNED-PAYLOAD";

        const parsed = parseAuthHeader(auth_header) orelse return acl_ctx;
        const credential = ctx.access_control_map.get(parsed.access_key);

        if (credential == null) {
            return acl_ctx;
        }

        const canonical = buildCanonicalRequest(
            allocator,
            req,
            parsed.signed_headers,
            x_amz_content_sha256,
        ) catch return acl_ctx;
        defer allocator.free(canonical);

        const string_to_sign = buildStringToSign(
            allocator,
            x_amz_date,
            parsed.date,
            parsed.region,
            parsed.service,
            canonical,
        ) catch return acl_ctx;
        defer allocator.free(string_to_sign);

        const calculated_sig = calculateSignature(
            allocator,
            credential.?.secret_key,
            parsed.date,
            parsed.region,
            parsed.service,
            string_to_sign,
        ) catch return acl_ctx;
        defer allocator.free(calculated_sig);

        if (std.mem.eql(u8, calculated_sig, parsed.signature)) {
            acl_ctx.authenticated = true;
            acl_ctx.role = credential.?.role;
        }

        return acl_ctx;
    }

    pub fn parseAuthHeader(header: []const u8) ?ParsedAuth {
        if (!std.mem.startsWith(u8, header, "AWS4-HMAC-SHA256 ")) return null;

        var result: ParsedAuth = undefined;

        const cred_start = std.mem.indexOf(u8, header, "Credential=") orelse return null;
        const cred_end = std.mem.indexOfPos(u8, header, cred_start, ",") orelse return null;
        const credential = header[cred_start + 11 .. cred_end];

        var cred_iter = std.mem.splitScalar(u8, credential, '/');
        result.access_key = cred_iter.next() orelse return null;
        result.date = cred_iter.next() orelse return null;
        result.region = cred_iter.next() orelse return null;
        result.service = cred_iter.next() orelse return null;

        const sh_start = std.mem.indexOf(u8, header, "SignedHeaders=") orelse return null;
        const sh_end = std.mem.indexOfPos(u8, header, sh_start, ",") orelse return null;
        result.signed_headers = header[sh_start + 14 .. sh_end];

        const sig_start = std.mem.indexOf(u8, header, "Signature=") orelse return null;
        result.signature = header[sig_start + 10 ..];

        return result;
    }

    fn buildCanonicalRequest(
        allocator: Allocator,
        req: *const Request,
        signed_headers: []const u8,
        payload_hash: []const u8,
    ) ![]const u8 {
        var result: std.ArrayListUnmanaged(u8) = .empty;
        errdefer result.deinit(allocator);

        try result.appendSlice(allocator, req.method);
        try result.append(allocator, '\n');

        // S3 uses single URI encoding — the path from the HTTP request line
        // is already URI-encoded, so use it as-is (no double-encoding)
        const canonical_path = if (req.path.len == 0) "/" else req.path;
        try result.appendSlice(allocator, canonical_path);
        try result.append(allocator, '\n');

        const sorted_query = try sortQueryString(allocator, req.query);
        defer allocator.free(sorted_query);
        try result.appendSlice(allocator, sorted_query);
        try result.append(allocator, '\n');

        var header_iter = std.mem.splitScalar(u8, signed_headers, ';');
        while (header_iter.next()) |header_name| {
            const value = req.header(header_name) orelse "";
            try result.appendSlice(allocator, header_name);
            try result.append(allocator, ':');
            try result.appendSlice(allocator, std.mem.trim(u8, value, " \t"));
            try result.append(allocator, '\n');
        }
        try result.append(allocator, '\n');

        try result.appendSlice(allocator, signed_headers);
        try result.append(allocator, '\n');

        try result.appendSlice(allocator, payload_hash);

        return result.toOwnedSlice(allocator);
    }

    fn buildStringToSign(
        allocator: Allocator,
        amz_date: []const u8,
        date_stamp: []const u8,
        region: []const u8,
        service: []const u8,
        canonical_request: []const u8,
    ) ![]const u8 {
        var result: std.ArrayListUnmanaged(u8) = .empty;
        errdefer result.deinit(allocator);

        try result.appendSlice(allocator, "AWS4-HMAC-SHA256\n");
        try result.appendSlice(allocator, amz_date);
        try result.append(allocator, '\n');

        try result.appendSlice(allocator, date_stamp);
        try result.append(allocator, '/');
        try result.appendSlice(allocator, region);
        try result.append(allocator, '/');
        try result.appendSlice(allocator, service);
        try result.appendSlice(allocator, "/aws4_request\n");

        const canonical_hash = hash(canonical_request);
        var hex_buf: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_buf, "{x}", .{canonical_hash}) catch unreachable;
        try result.appendSlice(allocator, &hex_buf);

        return result.toOwnedSlice(allocator);
    }

    fn calculateSignature(
        allocator: Allocator,
        secret_key: []const u8,
        date_stamp: []const u8,
        region: []const u8,
        service: []const u8,
        string_to_sign: []const u8,
    ) ![]const u8 {
        var k_secret_buf: [256]u8 = undefined;
        const k_secret_len = 4 + secret_key.len;
        @memcpy(k_secret_buf[0..4], "AWS4");
        @memcpy(k_secret_buf[4..k_secret_len], secret_key);

        const k_date = hmac(k_secret_buf[0..k_secret_len], date_stamp);
        const k_region = hmac(&k_date, region);
        const k_service = hmac(&k_region, service);
        const k_signing = hmac(&k_service, "aws4_request");
        const sig = hmac(&k_signing, string_to_sign);

        const hex = try allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{x}", .{sig}) catch unreachable;

        return hex;
    }

    pub fn hmac(key: []const u8, msg: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        HmacSha256.create(&out, msg, key);
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        Sha256.hash(data, &out, .{});
        return out;
    }
};

pub fn uriEncode(allocator: Allocator, input: []const u8, encode_slash: bool) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        if (isUnreserved(c) or (c == '/' and !encode_slash)) {
            try result.append(allocator, c);
        } else {
            try result.append(allocator, '%');
            const hex = "0123456789ABCDEF";
            try result.append(allocator, hex[c >> 4]);
            try result.append(allocator, hex[c & 0x0F]);
        }
    }

    return result.toOwnedSlice(allocator);
}

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '.' or c == '_' or c == '~';
}

pub fn uriDecode(allocator: Allocator, input: []const u8) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const high = hexDigitToInt(input[i + 1]) orelse {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            const low = hexDigitToInt(input[i + 2]) orelse {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, (high << 4) | low);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

fn hexDigitToInt(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return null;
}

pub fn sortQueryString(allocator: Allocator, query: []const u8) ![]const u8 {
    if (query.len == 0) return try allocator.dupe(u8, "");

    var pairs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer pairs.deinit(allocator);

    var normalized: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (normalized.items) |n| allocator.free(n);
        normalized.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (pair.len > 0) {
            // Normalize params without '=' to 'key=' format (required by SigV4)
            if (std.mem.indexOf(u8, pair, "=") == null) {
                const norm = try std.fmt.allocPrint(allocator, "{s}=", .{pair});
                try normalized.append(allocator, norm);
                try pairs.append(allocator, norm);
            } else {
                try pairs.append(allocator, pair);
            }
        }
    }

    std.mem.sort([]const u8, pairs.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    var result: std.ArrayListUnmanaged(u8) = .empty;
    for (pairs.items, 0..) |pair, i| {
        if (i > 0) try result.append(allocator, '&');
        try result.appendSlice(allocator, pair);
    }

    return result.toOwnedSlice(allocator);
}

fn handlePutObject(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    // Keys ending with '/' are folder markers — store as ".folder_marker" file
    const effective_key = if (key.len > 0 and key[key.len - 1] == '/')
        try std.fmt.allocPrint(allocator, "{s}.folder_marker", .{key})
    else
        try allocator.dupe(u8, key);
    defer allocator.free(effective_key);

    const path = try ctx.objectPath(allocator, bucket, effective_key);
    defer allocator.free(path);

    if (std.fs.path.dirname(path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    var file = std.fs.cwd().createFile(path, .{}) catch {
        sendError(res, 500, "InternalError", "Cannot create file");
        return;
    };
    defer file.close();

    file.writeAll(req.body) catch {
        sendError(res, 500, "InternalError", "Cannot write file");
        return;
    };

    // Use fast hash for ETag (wyhash is ~10x faster than SHA256)
    const hash = std.hash.Wyhash.hash(0, req.body);
    const etag = std.fmt.allocPrint(allocator, "\"{x}\"", .{hash}) catch {
        sendError(res, 500, "InternalError", "ETag failed");
        return;
    };

    res.ok();
    res.setHeader("ETag", etag);
}

fn handleGetObject(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const effective_key = if (key.len > 0 and key[key.len - 1] == '/')
        try std.fmt.allocPrint(allocator, "{s}.folder_marker", .{key})
    else
        try allocator.dupe(u8, key);
    defer allocator.free(effective_key);
    const path = try ctx.objectPath(allocator, bucket, effective_key);
    defer allocator.free(path);

    var file = std.fs.cwd().openFile(path, .{}) catch {
        sendError(res, 404, "NoSuchKey", "Object not found");
        return;
    };

    const stat = file.stat() catch {
        file.close();
        sendError(res, 500, "InternalError", "Stat failed");
        return;
    };

    const last_modified = allocHttpDate(allocator, @intCast(@divFloor(stat.mtime, std.time.ns_per_s))) catch {
        file.close();
        sendError(res, 500, "InternalError", "Date format failed");
        return;
    };

    // For range requests, use sendFile without ETag (efficient for large files)
    if (req.header("range")) |range_header| {
        if (parseRange(range_header, stat.size)) |range| {
            const len = range.end - range.start + 1;

            const content_range = std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{ range.start, range.end, stat.size }) catch {
                file.close();
                sendError(res, 500, "InternalError", "Range format failed");
                return;
            };

            res.status = 206;
            res.status_text = "Partial Content";
            res.setHeader("Content-Range", content_range);
            res.setHeader("Accept-Ranges", "bytes");
            res.setHeader("Last-Modified", last_modified);
            res.setSendFile(file, len, range.start);
            return;
        }
    }

    // For full file, read content to compute ETag
    const content = file.readToEndAlloc(allocator, MAX_BODY_SIZE) catch {
        file.close();
        sendError(res, 500, "InternalError", "Read failed");
        return;
    };
    file.close();

    const hash = std.hash.Wyhash.hash(0, content);
    const etag = std.fmt.allocPrint(allocator, "\"{x}\"", .{hash}) catch {
        sendError(res, 500, "InternalError", "ETag failed");
        return;
    };

    res.ok();
    res.setHeader("Accept-Ranges", "bytes");
    res.setHeader("ETag", etag);
    res.setHeader("Last-Modified", last_modified);
    res.body = content;
}

fn handleDeleteObject(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const effective_key = if (key.len > 0 and key[key.len - 1] == '/')
        try std.fmt.allocPrint(allocator, "{s}.folder_marker", .{key})
    else
        try allocator.dupe(u8, key);
    defer allocator.free(effective_key);
    const path = try ctx.objectPath(allocator, bucket, effective_key);
    defer allocator.free(path);

    deleteObjectInternal(ctx, allocator, bucket, path);
    res.noContent();
}

fn deleteObjectInternal(ctx: *const S3Context, allocator: Allocator, bucket: []const u8, path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.log.warn("delete failed: {}", .{err}),
    };

    // Clean up empty parent directories up to bucket level
    const bucket_path = ctx.bucketPath(allocator, bucket) catch return;
    defer allocator.free(bucket_path);

    var dir_path = std.fs.path.dirname(path);
    while (dir_path) |dp| {
        if (dp.len <= bucket_path.len) break;
        std.fs.cwd().deleteDir(dp) catch break;
        dir_path = std.fs.path.dirname(dp);
    }
}

fn handleDeleteObjects(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    // Parse XML body: <Delete><Object><Key>...</Key></Object>...</Delete>
    var xml: std.ArrayListUnmanaged(u8) = .empty;
    defer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try xml.appendSlice(allocator, "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    // Simple XML parsing - find all <Key>...</Key> pairs
    var body = req.body;

    while (std.mem.indexOf(u8, body, "<Key>")) |start| {
        const key_start = start + 5;
        const end = std.mem.indexOf(u8, body[key_start..], "</Key>") orelse break;
        const key = body[key_start .. key_start + end];

        if (key.len > 0 and isValidKey(key)) {
            const path = ctx.objectPath(allocator, bucket, key) catch continue;
            defer allocator.free(path);

            deleteObjectInternal(ctx, allocator, bucket, path);

            try xml.appendSlice(allocator, "<Deleted><Key>");
            try xmlEscape(allocator, &xml, key);
            try xml.appendSlice(allocator, "</Key></Deleted>");
        }

        body = body[key_start + end + 6 ..];
    }

    try xml.appendSlice(allocator, "</DeleteResult>");

    res.ok();
    res.setXmlBody(try xml.toOwnedSlice(allocator));
}

fn handleHeadObject(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const effective_key = if (key.len > 0 and key[key.len - 1] == '/')
        try std.fmt.allocPrint(allocator, "{s}.folder_marker", .{key})
    else
        try allocator.dupe(u8, key);
    defer allocator.free(effective_key);
    const path = try ctx.objectPath(allocator, bucket, effective_key);
    defer allocator.free(path);

    var file = std.fs.cwd().openFile(path, .{}) catch {
        sendError(res, 404, "NoSuchKey", "Object not found");
        return;
    };
    defer file.close();

    const stat = file.stat() catch {
        sendError(res, 500, "InternalError", "Stat failed");
        return;
    };

    // Compute ETag from file content (same as PUT uses)
    const content = file.readToEndAlloc(allocator, MAX_BODY_SIZE) catch {
        sendError(res, 500, "InternalError", "Read failed");
        return;
    };
    defer allocator.free(content);

    const hash = std.hash.Wyhash.hash(0, content);
    const etag = std.fmt.allocPrint(allocator, "\"{x}\"", .{hash}) catch {
        sendError(res, 500, "InternalError", "ETag failed");
        return;
    };

    const len_str = std.fmt.allocPrint(allocator, "{d}", .{stat.size}) catch {
        sendError(res, 500, "InternalError", "Format failed");
        return;
    };

    const last_modified = allocHttpDate(allocator, @intCast(@divFloor(stat.mtime, std.time.ns_per_s))) catch {
        sendError(res, 500, "InternalError", "Date format failed");
        return;
    };

    res.ok();
    res.setHeader("Content-Length", len_str);
    res.setHeader("Accept-Ranges", "bytes");
    res.setHeader("ETag", etag);
    res.setHeader("Last-Modified", last_modified);
}

fn handleListObjects(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const prefix_raw = getQueryParam(req.query, "prefix") orelse "";
    const prefix = try uriDecode(allocator, prefix_raw);
    defer allocator.free(prefix);

    const max_keys_str = getQueryParam(req.query, "max-keys") orelse "1000";
    const max_keys = std.fmt.parseInt(usize, max_keys_str, 10) catch 1000;

    const delimiter_raw = getQueryParam(req.query, "delimiter");
    const delimiter_decoded = if (delimiter_raw) |d| try uriDecode(allocator, d) else null;
    defer if (delimiter_decoded) |d| allocator.free(d);
    // Treat empty delimiter the same as no delimiter
    const delimiter = if (delimiter_decoded) |d| (if (d.len > 0) d else null) else null;

    const continuation_raw = getQueryParam(req.query, "continuation-token");
    const continuation = if (continuation_raw) |c| try uriDecode(allocator, c) else null;
    defer if (continuation) |c| allocator.free(c);

    const bucket_path = try ctx.bucketPath(allocator, bucket);
    defer allocator.free(bucket_path);

    var dir = std.fs.cwd().openDir(bucket_path, .{ .iterate = true }) catch {
        sendError(res, 404, "NoSuchBucket", "Bucket not found");
        return;
    };
    defer dir.close();

    var xml: std.ArrayListUnmanaged(u8) = .empty;
    defer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try xml.appendSlice(allocator, "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    try xml.appendSlice(allocator, "<Name>");
    try xmlEscape(allocator, &xml, bucket);
    try xml.appendSlice(allocator, "</Name><Prefix>");
    try xmlEscape(allocator, &xml, prefix);
    try xml.appendSlice(allocator, "</Prefix><MaxKeys>");
    var max_keys_num_buf: [32]u8 = undefined;
    const max_keys_num_str = std.fmt.bufPrint(&max_keys_num_buf, "{d}", .{max_keys}) catch "1000";
    try xml.appendSlice(allocator, max_keys_num_str);
    try xml.appendSlice(allocator, "</MaxKeys>");

    var keys: std.ArrayListUnmanaged(KeyInfo) = .empty;
    defer keys.deinit(allocator);

    try collectKeys(allocator, bucket_path, "", prefix, &keys);

    std.mem.sort(KeyInfo, keys.items, {}, struct {
        fn lessThan(_: void, a: KeyInfo, b: KeyInfo) bool {
            return std.mem.order(u8, a.key, b.key) == .lt;
        }
    }.lessThan);

    var start_idx: usize = 0;
    if (continuation) |cont| {
        for (keys.items, 0..) |item, i| {
            if (std.mem.eql(u8, item.key, cont)) {
                start_idx = i;
                break;
            }
        }
    }

    var common_prefixes = std.StringHashMap(void).init(allocator);
    defer common_prefixes.deinit();

    var count: usize = 0;
    var is_truncated = false;
    var next_token: ?[]const u8 = null;

    for (keys.items[start_idx..]) |item| {
        if (count >= max_keys) {
            is_truncated = true;
            next_token = item.key;
            break;
        }

        if (delimiter) |delim| {
            const after_prefix = if (prefix.len > 0 and std.mem.startsWith(u8, item.key, prefix))
                item.key[prefix.len..]
            else
                item.key;

            if (std.mem.indexOf(u8, after_prefix, delim)) |delim_idx| {
                const common_prefix = item.key[0 .. prefix.len + delim_idx + delim.len];
                if (!common_prefixes.contains(common_prefix)) {
                    try common_prefixes.put(common_prefix, {});
                    try xml.appendSlice(allocator, "<CommonPrefixes><Prefix>");
                    try xmlEscape(allocator, &xml, common_prefix);
                    try xml.appendSlice(allocator, "</Prefix></CommonPrefixes>");
                    count += 1;
                }
                continue;
            }
        }

        try xml.appendSlice(allocator, "<Contents><Key>");
        try xmlEscape(allocator, &xml, item.key);
        try xml.appendSlice(allocator, "</Key><LastModified>");
        var iso_buf: [20]u8 = undefined;
        formatIso8601(&iso_buf, item.mtime);
        try xml.appendSlice(allocator, &iso_buf);
        try xml.appendSlice(allocator, "</LastModified><Size>");
        var size_buf: [32]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{item.size}) catch "0";
        try xml.appendSlice(allocator, size_str);
        try xml.appendSlice(allocator, "</Size><StorageClass>STANDARD</StorageClass></Contents>");
        count += 1;
    }

    var count_buf: [32]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{count}) catch "0";
    try xml.appendSlice(allocator, "<KeyCount>");
    try xml.appendSlice(allocator, count_str);
    try xml.appendSlice(allocator, "</KeyCount>");

    if (is_truncated) {
        try xml.appendSlice(allocator, "<IsTruncated>true</IsTruncated>");
        if (next_token) |token| {
            try xml.appendSlice(allocator, "<NextContinuationToken>");
            try xmlEscape(allocator, &xml, token);
            try xml.appendSlice(allocator, "</NextContinuationToken>");
        }
    } else {
        try xml.appendSlice(allocator, "<IsTruncated>false</IsTruncated>");
    }

    try xml.appendSlice(allocator, "</ListBucketResult>");

    res.ok();
    res.setXmlBody(try xml.toOwnedSlice(allocator));
}

const KeyInfo = struct {
    key: []const u8,
    size: u64,
    mtime: i64, // Unix timestamp in seconds
};

fn collectKeys(allocator: Allocator, base_path: []const u8, current_prefix: []const u8, filter_prefix: []const u8, keys: *std.ArrayListUnmanaged(KeyInfo)) !void {
    const full_path = if (current_prefix.len > 0)
        try std.fs.path.join(allocator, &[_][]const u8{ base_path, current_prefix })
    else
        try allocator.dupe(u8, base_path);
    defer allocator.free(full_path);

    var dir = std.fs.cwd().openDir(full_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.name[0] == '.') continue;

        const full_key = if (current_prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ current_prefix, entry.name })
        else
            try allocator.dupe(u8, entry.name);

        if (entry.kind == .directory) {
            try collectKeys(allocator, base_path, full_key, filter_prefix, keys);
            allocator.free(full_key);
        } else if (entry.kind == .file) {
            // Translate .folder_marker files back to keys ending with /
            const report_key = if (std.mem.endsWith(u8, full_key, ".folder_marker")) blk: {
                const trimmed = try allocator.dupe(u8, full_key[0 .. full_key.len - ".folder_marker".len]);
                allocator.free(full_key);
                break :blk trimmed;
            } else full_key;

            if (filter_prefix.len == 0 or std.mem.startsWith(u8, report_key, filter_prefix)) {
                // Use statFile instead of open+stat+close - much faster
                const size, const mtime = blk: {
                    const stat = dir.statFile(entry.name) catch break :blk .{ 0, @as(i64, 0) };
                    break :blk .{ stat.size, @as(i64, @intCast(@divFloor(stat.mtime, std.time.ns_per_s))) };
                };
                try keys.append(allocator, .{ .key = report_key, .size = size, .mtime = mtime });
            } else {
                allocator.free(report_key);
            }
        }
    }
}

fn handleCreateBucket(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const path = try ctx.bucketPath(allocator, bucket);
    defer allocator.free(path);

    std.fs.cwd().makeDir(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            sendError(res, 500, "InternalError", "Cannot create bucket");
            return;
        },
    };

    res.ok();
}

fn handleHeadBucket(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const path = try ctx.bucketPath(allocator, bucket);
    defer allocator.free(path);

    var dir = std.fs.cwd().openDir(path, .{}) catch {
        sendError(res, 404, "NoSuchBucket", "Bucket not found");
        return;
    };
    dir.close();

    res.ok();
}

fn handleDeleteBucket(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const path = try ctx.bucketPath(allocator, bucket);
    defer allocator.free(path);

    std.fs.cwd().deleteDir(path) catch |err| switch (err) {
        error.DirNotEmpty => {
            sendError(res, 409, "BucketNotEmpty", "Bucket is not empty");
            return;
        },
        error.FileNotFound => {
            sendError(res, 404, "NoSuchBucket", "Bucket does not exist");
            return;
        },
        else => std.log.warn("delete bucket failed: {}", .{err}),
    };

    res.noContent();
}

fn handleListBuckets(ctx: *const S3Context, allocator: Allocator, res: *Response) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    var dir = std.fs.cwd().openDir(ctx.data_dir, .{ .iterate = true }) catch {
        sendError(res, 500, "InternalError", "Cannot open data dir");
        return;
    };
    defer dir.close();

    var xml: std.ArrayListUnmanaged(u8) = .empty;
    defer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try xml.appendSlice(allocator, "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    try xml.appendSlice(allocator, "<Owner><ID>minioadmin</ID><DisplayName>minioadmin</DisplayName></Owner>");
    try xml.appendSlice(allocator, "<Buckets>");

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name[0] == '.') continue;

        try xml.appendSlice(allocator, "<Bucket><Name>");
        try xmlEscape(allocator, &xml, entry.name);
        try xml.appendSlice(allocator, "</Name><CreationDate>");
        const mtime: i64 = blk: {
            const stat = dir.statFile(entry.name) catch break :blk 0;
            break :blk @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        };
        var iso_buf: [20]u8 = undefined;
        formatIso8601(&iso_buf, mtime);
        try xml.appendSlice(allocator, &iso_buf);
        try xml.appendSlice(allocator, "</CreationDate></Bucket>");
    }

    try xml.appendSlice(allocator, "</Buckets></ListAllMyBucketsResult>");

    res.ok();
    res.setXmlBody(try xml.toOwnedSlice(allocator));
}

fn handleInitiateMultipart(ctx: *const S3Context, allocator: Allocator, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    // Generate unique upload ID using timestamp + random bytes to prevent collision
    const timestamp: u64 = @intCast(std.time.timestamp());
    var random_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const random_suffix = std.mem.readInt(u64, &random_bytes, .little);
    var upload_id_buf: [32]u8 = undefined;
    const upload_id = std.fmt.bufPrint(&upload_id_buf, "{x}{x}", .{ timestamp, random_suffix }) catch unreachable;

    const parts_dir = std.fmt.allocPrint(allocator, "{s}/.uploads/{s}", .{ ctx.data_dir, upload_id }) catch return;
    defer allocator.free(parts_dir);
    std.fs.cwd().makePath(parts_dir) catch {};

    const meta_path = std.fmt.allocPrint(allocator, "{s}/.uploads/{s}/.meta", .{ ctx.data_dir, upload_id }) catch return;
    defer allocator.free(meta_path);

    var meta_file = std.fs.cwd().createFile(meta_path, .{}) catch return;
    defer meta_file.close();
    const meta_content = std.fmt.allocPrint(allocator, "{s}\n{s}", .{ bucket, key }) catch return;
    defer allocator.free(meta_content);
    meta_file.writeAll(meta_content) catch {};

    var xml: std.ArrayListUnmanaged(u8) = .empty;
    defer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try xml.appendSlice(allocator, "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    try xml.appendSlice(allocator, "<Bucket>");
    try xml.appendSlice(allocator, bucket);
    try xml.appendSlice(allocator, "</Bucket><Key>");
    try xmlEscape(allocator, &xml, key);
    try xml.appendSlice(allocator, "</Key><UploadId>");
    try xml.appendSlice(allocator, upload_id);
    try xml.appendSlice(allocator, "</UploadId></InitiateMultipartUploadResult>");

    res.ok();
    res.setXmlBody(try xml.toOwnedSlice(allocator));
}

fn handleUploadPart(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    _ = bucket;
    _ = key;

    const upload_id = getQueryParam(req.query, "uploadId") orelse {
        sendError(res, 400, "InvalidRequest", "Missing uploadId");
        return;
    };
    if (!isValidUploadId(upload_id)) {
        sendError(res, 400, "InvalidArgument", "Invalid uploadId");
        return;
    }
    const part_number = getQueryParam(req.query, "partNumber") orelse {
        sendError(res, 400, "InvalidRequest", "Missing partNumber");
        return;
    };
    _ = std.fmt.parseInt(u32, part_number, 10) catch {
        sendError(res, 400, "InvalidArgument", "Invalid partNumber");
        return;
    };

    const part_path = std.fmt.allocPrint(allocator, "{s}/.uploads/{s}/{s}", .{ ctx.data_dir, upload_id, part_number }) catch return;
    defer allocator.free(part_path);

    var file = std.fs.cwd().createFile(part_path, .{}) catch {
        sendError(res, 500, "InternalError", "Cannot create part file");
        return;
    };
    defer file.close();

    file.writeAll(req.body) catch {
        sendError(res, 500, "InternalError", "Cannot write part");
        return;
    };

    const etag_hash = SigV4.hash(req.body);
    const etag = try std.fmt.allocPrint(allocator, "\"{x}\"", .{etag_hash});

    res.ok();
    res.setHeader("ETag", etag);
}

fn handleCompleteMultipart(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response, bucket: []const u8, key: []const u8) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const upload_id = getQueryParam(req.query, "uploadId") orelse {
        sendError(res, 400, "InvalidRequest", "Missing uploadId");
        return;
    };
    if (!isValidUploadId(upload_id)) {
        sendError(res, 400, "InvalidArgument", "Invalid uploadId");
        return;
    }

    const parts_dir = std.fmt.allocPrint(allocator, "{s}/.uploads/{s}", .{ ctx.data_dir, upload_id }) catch {
        sendError(res, 500, "InternalError", "Allocation failed");
        return;
    };
    defer allocator.free(parts_dir);

    const final_path = try ctx.objectPath(allocator, bucket, key);
    defer allocator.free(final_path);

    if (std.fs.path.dirname(final_path)) |dir| {
        std.fs.cwd().makePath(dir) catch |err| {
            std.log.warn("makePath failed: {}", .{err});
        };
    }

    var final_file = std.fs.cwd().createFile(final_path, .{}) catch {
        sendError(res, 500, "InternalError", "Cannot create final file");
        return;
    };
    defer final_file.close();

    var dir = std.fs.cwd().openDir(parts_dir, .{ .iterate = true }) catch {
        sendError(res, 404, "NoSuchUpload", "Upload not found");
        return;
    };
    defer dir.close();

    var parts: std.ArrayListUnmanaged(u32) = .empty;
    defer parts.deinit(allocator);

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file and entry.name[0] != '.') {
            const num = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            try parts.append(allocator, num);
        }
    }

    std.mem.sort(u32, parts.items, {}, std.sort.asc(u32));

    var hasher = std.crypto.hash.Md5.init(.{});
    var parts_assembled: usize = 0;

    for (parts.items) |part_num| {
        var part_num_buf: [16]u8 = undefined;
        const part_num_str = std.fmt.bufPrint(&part_num_buf, "{d}", .{part_num}) catch continue;
        const part_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ parts_dir, part_num_str }) catch {
            std.log.warn("allocation failed for part path", .{});
            continue;
        };
        defer allocator.free(part_path);

        var part_file = std.fs.cwd().openFile(part_path, .{}) catch |err| {
            std.log.warn("failed to open part {d}: {}", .{ part_num, err });
            continue;
        };
        defer part_file.close();

        const stat = part_file.stat() catch continue;
        const data = allocator.alloc(u8, stat.size) catch continue;
        defer allocator.free(data);

        const bytes_read = part_file.readAll(data) catch continue;
        final_file.writeAll(data[0..bytes_read]) catch |err| {
            std.log.warn("failed to write part {d}: {}", .{ part_num, err });
            continue;
        };

        var part_hash: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(data[0..bytes_read], &part_hash, .{});
        hasher.update(&part_hash);
        parts_assembled += 1;
    }

    std.fs.cwd().deleteTree(parts_dir) catch |err| {
        std.log.warn("failed to cleanup upload dir: {}", .{err});
    };

    var final_hash: [16]u8 = undefined;
    hasher.final(&final_hash);

    var xml: std.ArrayListUnmanaged(u8) = .empty;
    defer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try xml.appendSlice(allocator, "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    try xml.appendSlice(allocator, "<Bucket>");
    try xml.appendSlice(allocator, bucket);
    try xml.appendSlice(allocator, "</Bucket><Key>");
    try xmlEscape(allocator, &xml, key);

    var etag_buf: [72]u8 = undefined;
    const etag = std.fmt.bufPrint(&etag_buf, "</Key><ETag>\"{x}-{d}\"</ETag>", .{ final_hash, parts_assembled }) catch "</Key><ETag>\"\"</ETag>";
    try xml.appendSlice(allocator, etag);
    try xml.appendSlice(allocator, "</CompleteMultipartUploadResult>");

    res.ok();
    res.setXmlBody(try xml.toOwnedSlice(allocator));
}

fn handleAbortMultipart(ctx: *const S3Context, allocator: Allocator, req: *Request, res: *Response) !void {
    const tracy_fun = trace(@src());
    defer tracy_fun.end();

    const upload_id = getQueryParam(req.query, "uploadId") orelse {
        sendError(res, 400, "InvalidRequest", "Missing uploadId");
        return;
    };
    if (!isValidUploadId(upload_id)) {
        sendError(res, 400, "InvalidArgument", "Invalid uploadId");
        return;
    }

    const parts_dir = std.fmt.allocPrint(allocator, "{s}/.uploads/{s}", .{ ctx.data_dir, upload_id }) catch {
        sendError(res, 500, "InternalError", "Allocation failed");
        return;
    };
    defer allocator.free(parts_dir);

    std.fs.cwd().deleteTree(parts_dir) catch |err| {
        std.log.warn("abort multipart cleanup failed: {}", .{err});
    };

    res.noContent();
}

pub const Range = struct { start: u64, end: u64 };

pub fn parseRange(header: []const u8, file_size: u64) ?Range {
    if (!std.mem.startsWith(u8, header, "bytes=")) return null;
    const range_spec = header[6..];

    const dash = std.mem.indexOf(u8, range_spec, "-") orelse return null;
    const start_str = range_spec[0..dash];
    const end_str = range_spec[dash + 1 ..];

    // Suffix range: bytes=-N means last N bytes (clamp to file size per RFC 7233)
    if (start_str.len == 0 and end_str.len > 0) {
        const suffix_len = std.fmt.parseInt(u64, end_str, 10) catch return null;
        if (suffix_len == 0) return null;
        const actual = @min(suffix_len, file_size);
        return .{ .start = file_size - actual, .end = file_size - 1 };
    }

    if (file_size == 0) return null;
    const start = if (start_str.len > 0) std.fmt.parseInt(u64, start_str, 10) catch return null else 0;
    const end = if (end_str.len > 0) std.fmt.parseInt(u64, end_str, 10) catch return null else file_size - 1;

    if (start > end or end >= file_size) return null;
    return .{ .start = start, .end = end };
}

pub fn hasQuery(query: []const u8, key: []const u8) bool {
    if (std.mem.indexOf(u8, query, key)) |idx| {
        const at_start = (idx == 0) or (query[idx - 1] == '&');
        const end = idx + key.len;
        const at_end = (end == query.len) or (query[end] == '&') or (query[end] == '=');
        if (at_start and at_end) return true;
    }
    return false;
}

pub fn getQueryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (std.mem.indexOf(u8, pair, "=")) |eq_idx| {
            if (std.mem.eql(u8, pair[0..eq_idx], key)) {
                return pair[eq_idx + 1 ..];
            }
        } else {
            if (std.mem.eql(u8, pair, key)) {
                return "";
            }
        }
    }
    return null;
}

pub fn xmlEscape(allocator: Allocator, list: *std.ArrayListUnmanaged(u8), input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '<' => try list.appendSlice(allocator, "&lt;"),
            '>' => try list.appendSlice(allocator, "&gt;"),
            '&' => try list.appendSlice(allocator, "&amp;"),
            '"' => try list.appendSlice(allocator, "&quot;"),
            '\'' => try list.appendSlice(allocator, "&apos;"),
            else => try list.append(allocator, c),
        }
    }
}

fn sendError(res: *Response, status: u16, code: []const u8, message: []const u8) void {
    res.status = status;
    res.status_text = switch (status) {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        else => "Error",
    };
    res.setHeader("Content-Type", "application/xml");

    res.body = std.fmt.allocPrint(res.allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{s}</Code><Message>{s}</Message></Error>", .{ code, message }) catch return;
}
