// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Elixir Lexer and Recursive-Descent AST Parser for Quintessence.
//
// Parses the sequential Layer A functional subset, Layer B GenServer Face and
// `@choreography` declarations, and Layer C `use Quintessence.Nif` stubs with
// exact `line:col` source locations.

const std = @import("std");

pub const TokKind = enum {
    ident,
    alias_ident, // Capitalized: Verisim, GenServer, ...
    atom, // :ok, :sha256, ...
    int_lit,
    str_lit,
    at, // @
    dot, // .
    comma, // ,
    colon, // :
    lparen,
    rparen,
    lbracket,
    rbracket,
    lbrace,
    rbrace,
    map_open, // %{
    bin_open, // <<
    bin_close, // >>
    pipe_bar, // |
    pipe_op, // |>
    arrow, // ->
    eq, // =
    eqeq, // ==
    neq, // !=
    lt,
    le,
    gt,
    ge,
    plus,
    minus,
    star,
    slash,
    kw_defmodule,
    kw_def,
    kw_defp,
    kw_do,
    kw_end,
    kw_case,
    kw_if,
    kw_else,
    kw_fn,
    kw_when,
    kw_and,
    kw_or,
    kw_not,
    kw_true,
    kw_false,
    kw_use,
    kw_import,
    kw_alias,
    kw_receive,
    eof,
};

pub const Token = struct {
    kind: TokKind,
    lexeme: []const u8,
    line: usize,
    col: usize,
};

pub fn tokenize(alloc: std.mem.Allocator, src: []const u8) ![]Token {
    var list: std.ArrayList(Token) = .empty;
    var i: usize = 0;
    var line: usize = 1;
    var col: usize = 1;

    while (i < src.len) {
        const c = src[i];
        if (c == '\n') {
            i += 1;
            line += 1;
            col = 1;
            continue;
        }
        if (c == ' ' or c == '\t' or c == '\r' or c == ';') {
            i += 1;
            col += 1;
            continue;
        }
        if (c == '#') {
            while (i < src.len and src[i] != '\n') : (i += 1) {}
            continue;
        }
        // Triple-quoted heredoc or standard string literal
        if (c == '"') {
            const sl = line;
            const sc = col;
            if (i + 2 < src.len and src[i + 1] == '"' and src[i + 2] == '"') {
                const start = i;
                i += 3;
                col += 3;
                while (i + 2 < src.len) {
                    if (src[i] == '"' and src[i + 1] == '"' and src[i + 2] == '"') {
                        i += 3;
                        col += 3;
                        break;
                    }
                    if (src[i] == '\n') {
                        line += 1;
                        col = 1;
                    } else {
                        col += 1;
                    }
                    i += 1;
                }
                try list.append(alloc, .{ .kind = .str_lit, .lexeme = src[start..i], .line = sl, .col = sc });
                continue;
            } else {
                const start = i + 1;
                i += 1;
                col += 1;
                while (i < src.len and src[i] != '"') {
                    if (src[i] == '\\' and i + 1 < src.len) {
                        i += 2;
                        col += 2;
                        continue;
                    }
                    if (src[i] == '\n') {
                        line += 1;
                        col = 1;
                    } else {
                        col += 1;
                    }
                    i += 1;
                }
                const content = src[start..i];
                if (i < src.len and src[i] == '"') {
                    i += 1;
                    col += 1;
                }
                try list.append(alloc, .{ .kind = .str_lit, .lexeme = content, .line = sl, .col = sc });
                continue;
            }
        }
        // Multi-char operators & delimiters
        if (c == '%' and i + 1 < src.len and src[i + 1] == '{') {
            try list.append(alloc, .{ .kind = .map_open, .lexeme = "%{", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '<' and i + 1 < src.len and src[i + 1] == '<') {
            try list.append(alloc, .{ .kind = .bin_open, .lexeme = "<<", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '>' and i + 1 < src.len and src[i + 1] == '>') {
            try list.append(alloc, .{ .kind = .bin_close, .lexeme = ">>", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '|' and i + 1 < src.len and src[i + 1] == '>') {
            try list.append(alloc, .{ .kind = .pipe_op, .lexeme = "|>", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '-' and i + 1 < src.len and src[i + 1] == '>') {
            try list.append(alloc, .{ .kind = .arrow, .lexeme = "->", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '=' and i + 1 < src.len and src[i + 1] == '=') {
            try list.append(alloc, .{ .kind = .eqeq, .lexeme = "==", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '!' and i + 1 < src.len and src[i + 1] == '=') {
            try list.append(alloc, .{ .kind = .neq, .lexeme = "!=", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '<' and i + 1 < src.len and src[i + 1] == '=') {
            try list.append(alloc, .{ .kind = .le, .lexeme = "<=", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == '>' and i + 1 < src.len and src[i + 1] == '=') {
            try list.append(alloc, .{ .kind = .ge, .lexeme = ">=", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        if (c == ':' and i + 1 < src.len and src[i + 1] == ':') {
            try list.append(alloc, .{ .kind = .colon, .lexeme = "::", .line = line, .col = col });
            i += 2;
            col += 2;
            continue;
        }
        // Atom `:foo_bar`
        if (c == ':' and i + 1 < src.len and (std.ascii.isAlphabetic(src[i + 1]) or src[i + 1] == '_')) {
            const sl = line;
            const sc = col;
            const start = i + 1;
            i += 1;
            col += 1;
            while (i < src.len and (std.ascii.isAlphanumeric(src[i]) or src[i] == '_' or src[i] == '?' or src[i] == '!')) {
                i += 1;
                col += 1;
            }
            try list.append(alloc, .{ .kind = .atom, .lexeme = src[start..i], .line = sl, .col = sc });
            continue;
        }
        // Integer literal (with `_` separators or hex `0x...`)
        if (std.ascii.isDigit(c)) {
            const sl = line;
            const sc = col;
            const start = i;
            if (c == '0' and i + 1 < src.len and (src[i + 1] == 'x' or src[i + 1] == 'X')) {
                i += 2;
                col += 2;
                while (i < src.len and (std.ascii.isHex(src[i]) or src[i] == '_')) {
                    i += 1;
                    col += 1;
                }
            } else {
                while (i < src.len and (std.ascii.isDigit(src[i]) or src[i] == '_')) {
                    i += 1;
                    col += 1;
                }
            }
            try list.append(alloc, .{ .kind = .int_lit, .lexeme = src[start..i], .line = sl, .col = sc });
            continue;
        }
        // Identifier, keyword, or Module alias
        if (std.ascii.isAlphabetic(c) or c == '_') {
            const sl = line;
            const sc = col;
            const start = i;
            const is_upper = std.ascii.isUpper(c);
            while (i < src.len and (std.ascii.isAlphanumeric(src[i]) or src[i] == '_' or src[i] == '?' or src[i] == '!')) {
                i += 1;
                col += 1;
            }
            const word = src[start..i];
            if (i < src.len and src[i] == ':') {
                // Keyword-list key `layer:` -> emit atom + colon so key-value pairs parse cleanly
                i += 1;
                col += 1;
                try list.append(alloc, .{ .kind = .atom, .lexeme = word, .line = sl, .col = sc });
                try list.append(alloc, .{ .kind = .colon, .lexeme = ":", .line = sl, .col = col - 1 });
                continue;
            }
            const kw: TokKind = if (is_upper)
                .alias_ident
            else if (std.mem.eql(u8, word, "defmodule"))
                .kw_defmodule
            else if (std.mem.eql(u8, word, "def"))
                .kw_def
            else if (std.mem.eql(u8, word, "defp"))
                .kw_defp
            else if (std.mem.eql(u8, word, "do"))
                .kw_do
            else if (std.mem.eql(u8, word, "end"))
                .kw_end
            else if (std.mem.eql(u8, word, "case"))
                .kw_case
            else if (std.mem.eql(u8, word, "if"))
                .kw_if
            else if (std.mem.eql(u8, word, "else"))
                .kw_else
            else if (std.mem.eql(u8, word, "fn"))
                .kw_fn
            else if (std.mem.eql(u8, word, "when"))
                .kw_when
            else if (std.mem.eql(u8, word, "and"))
                .kw_and
            else if (std.mem.eql(u8, word, "or"))
                .kw_or
            else if (std.mem.eql(u8, word, "not"))
                .kw_not
            else if (std.mem.eql(u8, word, "true"))
                .kw_true
            else if (std.mem.eql(u8, word, "false"))
                .kw_false
            else if (std.mem.eql(u8, word, "use"))
                .kw_use
            else if (std.mem.eql(u8, word, "import"))
                .kw_import
            else if (std.mem.eql(u8, word, "alias"))
                .kw_alias
            else if (std.mem.eql(u8, word, "receive"))
                .kw_receive
            else
                .ident;
            try list.append(alloc, .{ .kind = kw, .lexeme = word, .line = sl, .col = sc });
            continue;
        }
        // Single-character punctuation
        const single: ?TokKind = switch (c) {
            '@' => .at,
            '.' => .dot,
            ',' => .comma,
            ':' => .colon,
            '(' => .lparen,
            ')' => .rparen,
            '[' => .lbracket,
            ']' => .rbracket,
            '{' => .lbrace,
            '}' => .rbrace,
            '|' => .pipe_bar,
            '=' => .eq,
            '<' => .lt,
            '>' => .gt,
            '+' => .plus,
            '-' => .minus,
            '*' => .star,
            '/' => .slash,
            else => null,
        };
        if (single) |sk| {
            try list.append(alloc, .{ .kind = sk, .lexeme = src[i .. i + 1], .line = line, .col = col });
        }
        i += 1;
        col += 1;
    }

    try list.append(alloc, .{ .kind = .eof, .lexeme = "", .line = line, .col = col });
    return list.toOwnedSlice(alloc);
}

pub const Expr = union(enum) {
    int_val: i64,
    bool_val: bool,
    atom_val: []const u8,
    str_val: []const u8,
    bin_zeros: usize, // <<0::256>> -> 32 bytes
    var_ref: []const u8,
    attr_ref: []const u8, // @max_payload
    field_access: struct { base: *const Expr, field: []const u8 },
    unary_not: *const Expr,
    unary_neg: *const Expr,
    bin_op: struct { op: []const u8, lhs: *const Expr, rhs: *const Expr },
    call: struct {
        target_mod: ?[]const u8, // e.g. "Code", ":crypto", "Verisim.Nif"
        func: []const u8,
        args: []*const Expr,
        line: usize,
        col: usize,
    },
    tuple: []*const Expr,
    list_lit: []*const Expr,
    list_cons: struct { head: *const Expr, tail: *const Expr },
    kv_pair: struct { key: []const u8, val: *const Expr },
    map_lit: []*const Expr, // list of kv_pair
    map_update: struct { base: *const Expr, updates: []*const Expr },
    let_bind: struct { name: []const u8, val: *const Expr, body: *const Expr },
    if_expr: struct { cond: *const Expr, then_br: *const Expr, else_br: *const Expr },
    case_expr: struct { scrutinee: *const Expr, arms: []CaseArm },
    fn_anon: struct { params: [][]const u8, body: *const Expr },
    receive_expr: struct { line: usize, col: usize, has_catch_all: bool, arms: []CaseArm },
};

pub const CaseArm = struct {
    pattern: *const Expr,
    guard: ?*const Expr,
    body: *const Expr,
};

pub const NifDecl = struct {
    name: []const u8,
    arity: usize,
    schedule: []const u8, // "auto", "normal", "dirty_cpu", "dirty_io"
    budget_us: u64,
    line: usize,
    col: usize,
};

pub const ChoreographyMsg = struct {
    sender: []const u8,
    receiver: []const u8,
    tag: []const u8,
    fields: [][]const u8,
    line: usize,
};

pub const KnowledgeClaim = struct {
    observer: []const u8,
    subject: []const u8,
    fact: []const u8,
    fields: [][]const u8,
    transport_kind: []const u8, // "call", "cast", "send", "assumed"
    transport_tag: []const u8,
    epoch_checked: bool,
    after_commit: bool,
    line: usize,
    col: usize,
};

pub const FuncClause = struct {
    params: []*const Expr,
    guard: ?*const Expr,
    body: *const Expr,
    line: usize,
    col: usize,
};

pub const FuncDecl = struct {
    name: []const u8,
    is_private: bool,
    arity: usize,
    role: ?[]const u8,
    handles_kind: ?[]const u8, // "call" or "cast"
    handles_tag: ?[]const u8,
    pres: []*const Expr,
    posts: []*const Expr,
    measure: ?*const Expr,
    trusted: bool,
    clauses: []FuncClause,
    line: usize,
    col: usize,
};

pub const ModuleAst = struct {
    file: []const u8,
    name: []const u8,
    layer: ?[]const u8, // "a", "b", "c", or null
    uses_genserver: bool,
    is_nif_stub: bool,
    nif_library: ?[]const u8,
    nif_abi_mod: ?[]const u8,
    nif_receipt_path: ?[]const u8,
    constants: std.StringHashMapUnmanaged(i64),
    caps: [][]const u8,
    secrets: std.StringHashMapUnmanaged([]const u8), // field -> classification ("confidential", "public", ...)
    declassifications: [][]const u8, // fields explicitly declassified
    invariants: []*const Expr,
    budgets: std.StringHashMapUnmanaged(u64),
    roles: [][]const u8,
    messages: []ChoreographyMsg,
    knowledge_claims: []KnowledgeClaim,
    nifs: []NifDecl,
    funcs: []FuncDecl,
    mailbox_capacity: ?u64,
};

pub fn parseCleanInt(raw: []const u8) i64 {
    var clean: [64]u8 = undefined;
    var n: usize = 0;
    for (raw) |c| {
        if (c != '_' and n < clean.len) {
            clean[n] = c;
            n += 1;
        }
    }
    return std.fmt.parseInt(i64, clean[0..n], 0) catch 0;
}

const Parser = struct {
    alloc: std.mem.Allocator,
    toks: []const Token,
    pos: usize = 0,

    fn peek(self: *const Parser) Token {
        return self.toks[@min(self.pos, self.toks.len - 1)];
    }

    fn peekAt(self: *const Parser, offset: usize) Token {
        return self.toks[@min(self.pos + offset, self.toks.len - 1)];
    }

    fn advance(self: *Parser) Token {
        const t = self.peek();
        if (self.pos + 1 < self.toks.len) self.pos += 1;
        return t;
    }

    fn match(self: *Parser, kind: TokKind) bool {
        if (self.peek().kind == kind) {
            _ = self.advance();
            return true;
        }
        return false;
    }

    fn box(self: *Parser, e: Expr) !*const Expr {
        const p = try self.alloc.create(Expr);
        p.* = e;
        return p;
    }

    fn parseAliasPath(self: *Parser) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        const first = self.advance();
        try out.appendSlice(self.alloc, first.lexeme);
        while (self.peek().kind == .dot and self.peekAt(1).kind == .alias_ident) {
            _ = self.advance();
            try out.append(self.alloc, '.');
            try out.appendSlice(self.alloc, self.advance().lexeme);
        }
        return out.toOwnedSlice(self.alloc);
    }

    fn unwrapSpec(e: *const Expr) *const Expr {
        switch (e.*) {
            .call => |c| {
                if (c.target_mod == null and std.mem.eql(u8, c.func, "spec") and c.args.len >= 1) {
                    return c.args[0];
                }
            },
            else => {},
        }
        return e;
    }

    fn parseSeq(self: *Parser, stop1: TokKind, stop2: TokKind, stop3: TokKind) anyerror!*const Expr {
        var exprs: std.ArrayList(*const Expr) = .empty;
        while (self.peek().kind != .eof and
            self.peek().kind != stop1 and
            self.peek().kind != stop2 and
            self.peek().kind != stop3)
        {
            // Stop before next top-level arm `pat ->` inside case/fn after parsing arm body
            if (exprs.items.len > 0 and stop1 == .kw_end and self.isNextCaseArm()) break;

            const lhs = try self.parseExpr();
            if (self.match(.eq)) {
                const rhs = try self.parseExpr();
                const rest = try self.parseSeq(stop1, stop2, stop3);
                const var_name = switch (lhs.*) {
                    .var_ref => |v| v,
                    else => "_",
                };
                const bind = try self.box(.{ .let_bind = .{ .name = var_name, .val = rhs, .body = rest } });
                if (exprs.items.len == 0) return bind;
                try exprs.append(self.alloc, bind);
                break;
            }
            try exprs.append(self.alloc, lhs);
        }
        if (exprs.items.len == 0) return self.box(.{ .atom_val = "nil" });
        return exprs.items[exprs.items.len - 1];
    }

    fn isNextCaseArm(self: *const Parser) bool {
        // Scan ahead on the same statement up to 16 tokens for `->` before `case`/`fn`/`end`
        var k: usize = 0;
        var depth: isize = 0;
        while (k < 20) : (k += 1) {
            const tk = self.peekAt(k).kind;
            if (tk == .eof or tk == .kw_end or tk == .kw_case or tk == .kw_fn or tk == .kw_def or tk == .kw_defp) return false;
            if (tk == .lparen or tk == .lbrace or tk == .lbracket or tk == .map_open) depth += 1;
            if (tk == .rparen or tk == .rbrace or tk == .rbracket) {
                if (depth == 0) return false;
                depth -= 1;
            }
            if (depth == 0 and tk == .arrow) return true;
        }
        return false;
    }

    fn parseExpr(self: *Parser) anyerror!*const Expr {
        return self.parseOr();
    }

    fn parseOr(self: *Parser) anyerror!*const Expr {
        var left = try self.parseAnd();
        while (self.peek().kind == .kw_or) {
            _ = self.advance();
            const right = try self.parseAnd();
            left = try self.box(.{ .bin_op = .{ .op = "or", .lhs = left, .rhs = right } });
        }
        return left;
    }

    fn parseAnd(self: *Parser) anyerror!*const Expr {
        var left = try self.parseCmp();
        while (self.peek().kind == .kw_and) {
            _ = self.advance();
            const right = try self.parseCmp();
            left = try self.box(.{ .bin_op = .{ .op = "and", .lhs = left, .rhs = right } });
        }
        return left;
    }

    fn parseCmp(self: *Parser) anyerror!*const Expr {
        var left = try self.parsePipe();
        while (true) {
            const op: ?[]const u8 = switch (self.peek().kind) {
                .eqeq => "==",
                .neq => "!=",
                .lt => "<",
                .le => "<=",
                .gt => ">",
                .ge => ">=",
                else => null,
            };
            if (op) |o| {
                _ = self.advance();
                const right = try self.parsePipe();
                left = try self.box(.{ .bin_op = .{ .op = o, .lhs = left, .rhs = right } });
            } else break;
        }
        return left;
    }

    fn parsePipe(self: *Parser) anyerror!*const Expr {
        var left = try self.parseAdd();
        while (self.match(.pipe_op)) {
            const rhs = try self.parseAdd();
            switch (rhs.*) {
                .call => |c| {
                    var new_args: std.ArrayList(*const Expr) = .empty;
                    try new_args.append(self.alloc, left);
                    for (c.args) |a| try new_args.append(self.alloc, a);
                    left = try self.box(.{
                        .call = .{
                            .target_mod = c.target_mod,
                            .func = c.func,
                            .args = try new_args.toOwnedSlice(self.alloc),
                            .line = c.line,
                            .col = c.col,
                        },
                    });
                },
                else => left = rhs,
            }
        }
        return left;
    }

    fn parseAdd(self: *Parser) anyerror!*const Expr {
        var left = try self.parseMul();
        while (self.peek().kind == .plus or self.peek().kind == .minus) {
            const op = self.advance().lexeme;
            const right = try self.parseMul();
            left = try self.box(.{ .bin_op = .{ .op = op, .lhs = left, .rhs = right } });
        }
        return left;
    }

    fn parseMul(self: *Parser) anyerror!*const Expr {
        var left = try self.parseUnary();
        while (self.peek().kind == .star or self.peek().kind == .slash) {
            const op = self.advance().lexeme;
            const right = try self.parseUnary();
            left = try self.box(.{ .bin_op = .{ .op = op, .lhs = left, .rhs = right } });
        }
        return left;
    }

    fn parseUnary(self: *Parser) anyerror!*const Expr {
        if (self.match(.kw_not)) {
            return self.box(.{ .unary_not = try self.parseUnary() });
        }
        if (self.match(.minus)) {
            const sub = try self.parseUnary();
            if (sub.* == .int_val) return self.box(.{ .int_val = -sub.int_val });
            return self.box(.{ .unary_neg = sub });
        }
        return self.parsePostfix();
    }

    fn parseArgList(self: *Parser) anyerror![]*const Expr {
        var args: std.ArrayList(*const Expr) = .empty;
        while (self.peek().kind != .rparen and self.peek().kind != .eof) {
            if (self.peek().kind == .atom and self.peekAt(1).kind == .colon) {
                const k = self.advance().lexeme;
                _ = self.advance();
                const v = try self.parseExpr();
                try args.append(self.alloc, try self.box(.{ .kv_pair = .{ .key = k, .val = v } }));
            } else {
                try args.append(self.alloc, try self.parseExpr());
            }
            _ = self.match(.comma);
        }
        _ = self.match(.rparen);
        return args.toOwnedSlice(self.alloc);
    }

    fn parsePostfix(self: *Parser) anyerror!*const Expr {
        var base = try self.parsePrimary();
        while (self.peek().kind == .dot) {
            _ = self.advance();
            const member = self.advance();
            if (self.match(.lparen)) {
                const args = try self.parseArgList();
                const mod_name = switch (base.*) {
                    .var_ref => |v| v,
                    .atom_val => |a| try std.fmt.allocPrint(self.alloc, ":{s}", .{a}),
                    else => "dynamic",
                };
                base = try self.box(.{
                    .call = .{
                        .target_mod = mod_name,
                        .func = member.lexeme,
                        .args = args,
                        .line = member.line,
                        .col = member.col,
                    },
                });
            } else {
                base = try self.box(.{ .field_access = .{ .base = base, .field = member.lexeme } });
            }
        }
        return base;
    }

    fn parseCaseArms(self: *Parser) anyerror![]CaseArm {
        var arms: std.ArrayList(CaseArm) = .empty;
        while (self.peek().kind != .kw_end and self.peek().kind != .eof) {
            const pat = try self.parseExpr();
            const guard: ?*const Expr = if (self.match(.kw_when)) try self.parseExpr() else null;
            _ = self.match(.arrow);
            const body = try self.parseSeq(.kw_end, .eof, .eof);
            try arms.append(self.alloc, .{ .pattern = pat, .guard = guard, .body = body });
        }
        return arms.toOwnedSlice(self.alloc);
    }

    fn parsePrimary(self: *Parser) anyerror!*const Expr {
        const t = self.peek();
        switch (t.kind) {
            .int_lit => {
                _ = self.advance();
                return self.box(.{ .int_val = parseCleanInt(t.lexeme) });
            },
            .kw_true => {
                _ = self.advance();
                return self.box(.{ .bool_val = true });
            },
            .kw_false => {
                _ = self.advance();
                return self.box(.{ .bool_val = false });
            },
            .str_lit => {
                _ = self.advance();
                return self.box(.{ .str_val = t.lexeme });
            },
            .atom => {
                _ = self.advance();
                if (self.match(.colon)) {
                    const v = try self.parseExpr();
                    return self.box(.{ .kv_pair = .{ .key = t.lexeme, .val = v } });
                }
                return self.box(.{ .atom_val = t.lexeme });
            },
            .at => {
                _ = self.advance();
                const nm = self.advance();
                return self.box(.{ .attr_ref = nm.lexeme });
            },
            .alias_ident => {
                const mod_path = try self.parseAliasPath();
                return self.box(.{ .var_ref = mod_path });
            },
            .ident => {
                _ = self.advance();
                if (self.match(.lparen)) {
                    const args = try self.parseArgList();
                    return self.box(.{
                        .call = .{
                            .target_mod = null,
                            .func = t.lexeme,
                            .args = args,
                            .line = t.line,
                            .col = t.col,
                        },
                    });
                }
                if (self.match(.slash) and self.peek().kind == .int_lit) {
                    const ar = self.advance();
                    const combined = try std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ t.lexeme, ar.lexeme });
                    return self.box(.{ .atom_val = combined });
                }
                return self.box(.{ .var_ref = t.lexeme });
            },
            .lparen => {
                _ = self.advance();
                const inner = try self.parseExpr();
                _ = self.match(.rparen);
                return inner;
            },
            .lbrace => {
                _ = self.advance();
                var elems: std.ArrayList(*const Expr) = .empty;
                while (self.peek().kind != .rbrace and self.peek().kind != .eof) {
                    try elems.append(self.alloc, try self.parseExpr());
                    _ = self.match(.comma);
                }
                _ = self.match(.rbrace);
                return self.box(.{ .tuple = try elems.toOwnedSlice(self.alloc) });
            },
            .lbracket => {
                _ = self.advance();
                if (self.match(.rbracket)) return self.box(.{ .list_lit = &.{} });
                const first = try self.parseExpr();
                if (self.match(.pipe_bar)) {
                    const tail = try self.parseExpr();
                    _ = self.match(.rbracket);
                    return self.box(.{ .list_cons = .{ .head = first, .tail = tail } });
                }
                var items: std.ArrayList(*const Expr) = .empty;
                try items.append(self.alloc, first);
                while (self.match(.comma)) {
                    if (self.peek().kind == .rbracket) break;
                    try items.append(self.alloc, try self.parseExpr());
                }
                _ = self.match(.rbracket);
                return self.box(.{ .list_lit = try items.toOwnedSlice(self.alloc) });
            },
            .map_open => {
                _ = self.advance();
                if (self.match(.rbrace)) return self.box(.{ .map_lit = &.{} });
                const first = try self.parseExpr();
                if (self.match(.pipe_bar)) {
                    var updates: std.ArrayList(*const Expr) = .empty;
                    while (self.peek().kind != .rbrace and self.peek().kind != .eof) {
                        try updates.append(self.alloc, try self.parseExpr());
                        _ = self.match(.comma);
                    }
                    _ = self.match(.rbrace);
                    return self.box(.{ .map_update = .{ .base = first, .updates = try updates.toOwnedSlice(self.alloc) } });
                }
                var fields: std.ArrayList(*const Expr) = .empty;
                try fields.append(self.alloc, first);
                while (self.match(.comma)) {
                    if (self.peek().kind == .rbrace) break;
                    try fields.append(self.alloc, try self.parseExpr());
                }
                _ = self.match(.rbrace);
                return self.box(.{ .map_lit = try fields.toOwnedSlice(self.alloc) });
            },
            .bin_open => {
                _ = self.advance();
                var bits: usize = 0;
                var byte_count: usize = 0;
                while (self.peek().kind != .bin_close and self.peek().kind != .eof) {
                    const tok = self.advance();
                    if (tok.kind == .colon and self.peek().kind == .int_lit) {
                        bits = @intCast(parseCleanInt(self.advance().lexeme));
                    } else if (tok.kind == .int_lit) {
                        byte_count += 1;
                    }
                }
                _ = self.match(.bin_close);
                const bytes = if (bits > 0) bits / 8 else byte_count;
                return self.box(.{ .bin_zeros = bytes });
            },
            .kw_if => {
                _ = self.advance();
                const cond = try self.parseExpr();
                if (self.match(.comma)) {
                    // Inline `if cond, do: a, else: b`
                    _ = self.match(.atom); // do
                    _ = self.match(.colon);
                    const th = try self.parseExpr();
                    var el: *const Expr = try self.box(.{ .atom_val = "nil" });
                    if (self.match(.comma)) {
                        _ = self.match(.atom); // else
                        _ = self.match(.colon);
                        el = try self.parseExpr();
                    }
                    return self.box(.{ .if_expr = .{ .cond = cond, .then_br = th, .else_br = el } });
                }
                _ = self.match(.kw_do);
                const th = try self.parseSeq(.kw_else, .kw_end, .eof);
                var el: *const Expr = try self.box(.{ .atom_val = "nil" });
                if (self.match(.kw_else)) {
                    el = try self.parseSeq(.kw_end, .eof, .eof);
                }
                _ = self.match(.kw_end);
                return self.box(.{ .if_expr = .{ .cond = cond, .then_br = th, .else_br = el } });
            },
            .kw_case => {
                _ = self.advance();
                const scrut = try self.parseExpr();
                _ = self.match(.kw_do);
                const arms = try self.parseCaseArms();
                _ = self.match(.kw_end);
                return self.box(.{ .case_expr = .{ .scrutinee = scrut, .arms = arms } });
            },
            .kw_receive => {
                const rl = t.line;
                const rc = t.col;
                _ = self.advance();
                _ = self.match(.kw_do);
                const arms = try self.parseCaseArms();
                _ = self.match(.kw_end);
                var catch_all = false;
                for (arms) |arm| {
                    if (arm.pattern.* == .var_ref and arm.guard == null) catch_all = true;
                }
                return self.box(.{ .receive_expr = .{ .line = rl, .col = rc, .has_catch_all = catch_all, .arms = arms } });
            },
            .kw_fn => {
                _ = self.advance();
                var params: std.ArrayList([]const u8) = .empty;
                while (self.peek().kind != .arrow and self.peek().kind != .eof) {
                    const p = self.advance();
                    if (p.kind == .ident) try params.append(self.alloc, p.lexeme);
                }
                _ = self.match(.arrow);
                const body = try self.parseSeq(.kw_end, .eof, .eof);
                _ = self.match(.kw_end);
                return self.box(.{ .fn_anon = .{ .params = try params.toOwnedSlice(self.alloc), .body = body } });
            },
            else => {
                _ = self.advance();
                return self.box(.{ .atom_val = "unknown" });
            },
        }
    }
};

fn collectCapAtoms(alloc: std.mem.Allocator, e: *const Expr, out: *std.ArrayList([]const u8)) !void {
    switch (e.*) {
        .atom_val => |a| try out.append(alloc, a),
        .kv_pair => |kv| {
            try out.append(alloc, kv.key);
            try collectCapAtoms(alloc, kv.val, out);
        },
        .list_lit => |xs| for (xs) |x| try collectCapAtoms(alloc, x, out),
        .tuple => |xs| for (xs) |x| try collectCapAtoms(alloc, x, out),
        else => {},
    }
}

fn atomStr(e: *const Expr) []const u8 {
    return switch (e.*) {
        .atom_val => |a| a,
        .var_ref => |v| v,
        .str_val => |s| s,
        else => "",
    };
}

fn parseChoreographyList(
    alloc: std.mem.Allocator,
    e: *const Expr,
    roles: *std.ArrayList([]const u8),
    msgs: *std.ArrayList(ChoreographyMsg),
    claims: *std.ArrayList(KnowledgeClaim),
    line: usize,
    col: usize,
) !void {
    if (e.* != .list_lit) return;
    for (e.list_lit) |item| {
        if (item.* != .kv_pair) continue;
        const kv = item.kv_pair;
        if (std.mem.eql(u8, kv.key, "roles") and kv.val.* == .list_lit) {
            for (kv.val.list_lit) |r| try roles.append(alloc, atomStr(r));
        } else if (std.mem.eql(u8, kv.key, "messages") and kv.val.* == .list_lit) {
            for (kv.val.list_lit) |m| {
                if (m.* == .tuple and m.tuple.len >= 3) {
                    var flds: std.ArrayList([]const u8) = .empty;
                    if (m.tuple.len >= 4 and m.tuple[3].* == .list_lit) {
                        for (m.tuple[3].list_lit) |f| try flds.append(alloc, atomStr(f));
                    }
                    try msgs.append(alloc, .{
                        .sender = atomStr(m.tuple[0]),
                        .receiver = atomStr(m.tuple[1]),
                        .tag = atomStr(m.tuple[2]),
                        .fields = try flds.toOwnedSlice(alloc),
                        .line = line,
                    });
                }
            }
        } else if (std.mem.eql(u8, kv.key, "knowledge") and kv.val.* == .list_lit) {
            for (kv.val.list_lit) |k| {
                if (k.* == .tuple and k.tuple.len >= 5) {
                    var flds: std.ArrayList([]const u8) = .empty;
                    if (k.tuple[3].* == .list_lit) {
                        for (k.tuple[3].list_lit) |f| try flds.append(alloc, atomStr(f));
                    }
                    var tkind: []const u8 = "unknown";
                    var ttag: []const u8 = "";
                    var epoch_checked = true;
                    var after_commit = true;
                    if (k.tuple[4].* == .tuple and k.tuple[4].tuple.len >= 2) {
                        tkind = atomStr(k.tuple[4].tuple[0]);
                        ttag = atomStr(k.tuple[4].tuple[1]);
                        if (k.tuple[4].tuple.len >= 3) {
                            const opt = atomStr(k.tuple[4].tuple[2]);
                            if (std.mem.eql(u8, opt, "ignore_epoch")) epoch_checked = false;
                            if (std.mem.eql(u8, opt, "before_commit")) after_commit = false;
                        }
                    } else {
                        tkind = atomStr(k.tuple[4]);
                    }
                    try claims.append(alloc, .{
                        .observer = atomStr(k.tuple[0]),
                        .subject = atomStr(k.tuple[1]),
                        .fact = atomStr(k.tuple[2]),
                        .fields = try flds.toOwnedSlice(alloc),
                        .transport_kind = tkind,
                        .transport_tag = ttag,
                        .epoch_checked = epoch_checked,
                        .after_commit = after_commit,
                        .line = line,
                        .col = col,
                    });
                }
            }
        }
    }
}

pub fn parseFile(alloc: std.mem.Allocator, file_path: []const u8, src: []const u8) ![]ModuleAst {
    const toks = try tokenize(alloc, src);
    var p = Parser{ .alloc = alloc, .toks = toks };
    var mods: std.ArrayList(ModuleAst) = .empty;

    while (p.peek().kind != .eof) {
        if (!p.match(.kw_defmodule)) {
            _ = p.advance();
            continue;
        }
        const mod_name = try p.parseAliasPath();
        _ = p.match(.kw_do);

        var mod = ModuleAst{
            .file = file_path,
            .name = mod_name,
            .layer = null,
            .uses_genserver = false,
            .is_nif_stub = false,
            .nif_library = null,
            .nif_abi_mod = null,
            .nif_receipt_path = null,
            .constants = .{},
            .caps = &.{},
            .secrets = .{},
            .declassifications = &.{},
            .invariants = &.{},
            .budgets = .{},
            .roles = &.{},
            .messages = &.{},
            .knowledge_claims = &.{},
            .nifs = &.{},
            .funcs = &.{},
            .mailbox_capacity = null,
        };

        var caps: std.ArrayList([]const u8) = .empty;
        var declass: std.ArrayList([]const u8) = .empty;
        var invs: std.ArrayList(*const Expr) = .empty;
        var roles: std.ArrayList([]const u8) = .empty;
        var msgs: std.ArrayList(ChoreographyMsg) = .empty;
        var claims: std.ArrayList(KnowledgeClaim) = .empty;
        var nifs: std.ArrayList(NifDecl) = .empty;
        var funcs: std.ArrayList(FuncDecl) = .empty;

        // Pending function-level attributes
        var pend_pres: std.ArrayList(*const Expr) = .empty;
        var pend_posts: std.ArrayList(*const Expr) = .empty;
        var pend_measure: ?*const Expr = null;
        var pend_trusted = false;
        var pend_role: ?[]const u8 = null;
        var pend_hk: ?[]const u8 = null;
        var pend_ht: ?[]const u8 = null;
        var pend_nif: ?NifDecl = null;

        while (p.peek().kind != .kw_end and p.peek().kind != .eof) {
            const tk = p.peek();
            if (p.match(.kw_use)) {
                const target = try p.parseAliasPath();
                if (std.mem.eql(u8, target, "GenServer")) mod.uses_genserver = true;
                if (std.mem.eql(u8, target, "Quintessence.Nif")) mod.is_nif_stub = true;
                while (p.match(.comma)) {
                    const kv = try p.parseExpr();
                    if (kv.* == .kv_pair) {
                        const k = kv.kv_pair.key;
                        const v = kv.kv_pair.val;
                        if (std.mem.eql(u8, target, "Quintessence.Face") and std.mem.eql(u8, k, "layer")) {
                            mod.layer = atomStr(v);
                        } else if (std.mem.eql(u8, target, "Quintessence.Nif")) {
                            if (std.mem.eql(u8, k, "library")) mod.nif_library = atomStr(v);
                            if (std.mem.eql(u8, k, "abi")) mod.nif_abi_mod = atomStr(v);
                            if (std.mem.eql(u8, k, "receipt")) mod.nif_receipt_path = atomStr(v);
                        }
                    }
                }
                continue;
            }
            if (p.match(.kw_import) or p.match(.kw_alias)) {
                _ = try p.parseAliasPath();
                continue;
            }
            if (p.match(.at)) {
                const attr = p.advance();
                const aname = attr.lexeme;
                if (std.mem.eql(u8, aname, "moduledoc") or std.mem.eql(u8, aname, "doc") or std.mem.eql(u8, aname, "impl")) {
                    _ = try p.parseExpr();
                    continue;
                }
                if (std.mem.eql(u8, aname, "trusted")) {
                    _ = try p.parseExpr();
                    pend_trusted = true;
                    continue;
                }
                if (std.mem.eql(u8, aname, "pre")) {
                    try pend_pres.append(alloc, Parser.unwrapSpec(try p.parseExpr()));
                    continue;
                }
                if (std.mem.eql(u8, aname, "post")) {
                    try pend_posts.append(alloc, Parser.unwrapSpec(try p.parseExpr()));
                    continue;
                }
                if (std.mem.eql(u8, aname, "measure")) {
                    pend_measure = Parser.unwrapSpec(try p.parseExpr());
                    continue;
                }
                if (std.mem.eql(u8, aname, "invariant")) {
                    try invs.append(alloc, Parser.unwrapSpec(try p.parseExpr()));
                    continue;
                }
                if (std.mem.eql(u8, aname, "role")) {
                    pend_role = atomStr(try p.parseExpr());
                    continue;
                }
                if (std.mem.eql(u8, aname, "handles")) {
                    const h = try p.parseExpr();
                    if (h.* == .tuple and h.tuple.len >= 2) {
                        pend_hk = atomStr(h.tuple[0]);
                        pend_ht = atomStr(h.tuple[1]);
                    }
                    continue;
                }
                if (std.mem.eql(u8, aname, "mailbox_capacity")) {
                    const mc = try p.parseExpr();
                    if (mc.* == .int_val and mc.int_val > 0) mod.mailbox_capacity = @intCast(mc.int_val);
                    continue;
                }
                if (std.mem.eql(u8, aname, "cap")) {
                    const ce = try p.parseExpr();
                    try collectCapAtoms(alloc, ce, &caps);
                    continue;
                }
                if (std.mem.eql(u8, aname, "secret")) {
                    const se = try p.parseExpr();
                    if (se.* == .list_lit) {
                        for (se.list_lit) |item| {
                            if (item.* == .kv_pair) {
                                try mod.secrets.put(alloc, item.kv_pair.key, atomStr(item.kv_pair.val));
                            }
                        }
                    }
                    continue;
                }
                if (std.mem.eql(u8, aname, "declassify")) {
                    const first = try p.parseExpr();
                    if (first.* == .kv_pair) try declass.append(alloc, first.kv_pair.key);
                    while (p.match(.comma)) {
                        const nxt = try p.parseExpr();
                        if (nxt.* == .kv_pair and !std.mem.eql(u8, nxt.kv_pair.key, "reason")) {
                            try declass.append(alloc, nxt.kv_pair.key);
                        }
                    }
                    continue;
                }
                if (std.mem.eql(u8, aname, "budget")) {
                    const first = try p.parseExpr();
                    if (first.* == .kv_pair and first.kv_pair.val.* == .int_val) {
                        try mod.budgets.put(alloc, first.kv_pair.key, @intCast(first.kv_pair.val.int_val));
                    }
                    while (p.match(.comma)) {
                        const nxt = try p.parseExpr();
                        if (nxt.* == .kv_pair and nxt.kv_pair.val.* == .int_val) {
                            try mod.budgets.put(alloc, nxt.kv_pair.key, @intCast(nxt.kv_pair.val.int_val));
                        }
                    }
                    continue;
                }
                if (std.mem.eql(u8, aname, "choreography")) {
                    const ch = try p.parseExpr();
                    try parseChoreographyList(alloc, ch, &roles, &msgs, &claims, attr.line, attr.col);
                    continue;
                }
                if (std.mem.eql(u8, aname, "nif")) {
                    const nm = atomStr(try p.parseExpr());
                    var sched: []const u8 = "auto";
                    var bud: u64 = 1_000;
                    while (p.match(.comma)) {
                        const opt = try p.parseExpr();
                        if (opt.* == .kv_pair) {
                            if (std.mem.eql(u8, opt.kv_pair.key, "schedule")) sched = atomStr(opt.kv_pair.val);
                            if (std.mem.eql(u8, opt.kv_pair.key, "budget_us") and opt.kv_pair.val.* == .int_val) {
                                bud = @intCast(opt.kv_pair.val.int_val);
                            }
                        }
                    }
                    pend_nif = .{ .name = nm, .arity = 0, .schedule = sched, .budget_us = bud, .line = attr.line, .col = attr.col };
                    continue;
                }
                // Module integer constant `@max_payload 1_048_576`
                const val = try p.parseExpr();
                if (val.* == .int_val) {
                    try mod.constants.put(alloc, aname, val.int_val);
                }
                continue;
            }
            if (p.peek().kind == .kw_def or p.peek().kind == .kw_defp) {
                const is_priv = p.advance().kind == .kw_defp;
                const fn_tok = p.advance();
                var params: std.ArrayList(*const Expr) = .empty;
                if (p.match(.lparen)) {
                    while (p.peek().kind != .rparen and p.peek().kind != .eof) {
                        try params.append(alloc, try p.parseExpr());
                        _ = p.match(.comma);
                    }
                    _ = p.match(.rparen);
                }
                const guard: ?*const Expr = if (p.match(.kw_when)) try p.parseExpr() else null;
                var body: *const Expr = undefined;
                if (p.match(.comma)) {
                    _ = p.match(.atom); // do
                    _ = p.match(.colon);
                    body = try p.parseExpr();
                } else {
                    _ = p.match(.kw_do);
                    body = try p.parseSeq(.kw_end, .eof, .eof);
                    _ = p.match(.kw_end);
                }
                const pslice = try params.toOwnedSlice(alloc);
                if (pend_nif) |*nd| {
                    nd.arity = pslice.len;
                    try nifs.append(alloc, nd.*);
                    pend_nif = null;
                }
                const clause = FuncClause{
                    .params = pslice,
                    .guard = guard,
                    .body = body,
                    .line = fn_tok.line,
                    .col = fn_tok.col,
                };
                // Merge consecutive clauses of the same `def`/`defp` name & arity
                if (funcs.items.len > 0 and
                    std.mem.eql(u8, funcs.items[funcs.items.len - 1].name, fn_tok.lexeme) and
                    funcs.items[funcs.items.len - 1].arity == pslice.len and
                    pend_pres.items.len == 0 and pend_posts.items.len == 0 and pend_measure == null)
                {
                    var prev = &funcs.items[funcs.items.len - 1];
                    var merged: std.ArrayList(FuncClause) = .empty;
                    for (prev.clauses) |c| try merged.append(alloc, c);
                    try merged.append(alloc, clause);
                    prev.clauses = try merged.toOwnedSlice(alloc);
                } else {
                    var cl_list: std.ArrayList(FuncClause) = .empty;
                    try cl_list.append(alloc, clause);
                    try funcs.append(alloc, .{
                        .name = fn_tok.lexeme,
                        .is_private = is_priv,
                        .arity = pslice.len,
                        .role = pend_role,
                        .handles_kind = pend_hk,
                        .handles_tag = pend_ht,
                        .pres = try pend_pres.toOwnedSlice(alloc),
                        .posts = try pend_posts.toOwnedSlice(alloc),
                        .measure = pend_measure,
                        .trusted = pend_trusted,
                        .clauses = try cl_list.toOwnedSlice(alloc),
                        .line = fn_tok.line,
                        .col = fn_tok.col,
                    });
                    pend_pres = .empty;
                    pend_posts = .empty;
                    pend_measure = null;
                    pend_trusted = false;
                    pend_role = null;
                    pend_hk = null;
                    pend_ht = null;
                }
                continue;
            }
            _ = tk;
            _ = p.advance();
        }
        _ = p.match(.kw_end);

        mod.caps = try caps.toOwnedSlice(alloc);
        mod.declassifications = try declass.toOwnedSlice(alloc);
        mod.invariants = try invs.toOwnedSlice(alloc);
        mod.roles = try roles.toOwnedSlice(alloc);
        mod.messages = try msgs.toOwnedSlice(alloc);
        mod.knowledge_claims = try claims.toOwnedSlice(alloc);
        mod.nifs = try nifs.toOwnedSlice(alloc);
        mod.funcs = try funcs.toOwnedSlice(alloc);
        if (mod.is_nif_stub and mod.layer == null) mod.layer = "c";

        try mods.append(alloc, mod);
    }

    return mods.toOwnedSlice(alloc);
}
