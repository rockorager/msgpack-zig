# msgpack-zig

msgpack-zig provides a simple API for encoding and decoding msgpack data. The
API is designed to similar to `std.json`. Msgpack inherently requires less
allocation than JSON so the return values are slightly different.

> [!IMPORTANT]
> msgpack-zig uses zig 0.13.0

## Usage

> [!NOTE]
> Refer to the [documentation](https://github.com/rockorager/msgpack-zig) for additional usage.

There are two main functions provided by msgpack-zig:

```zig
/// Pack a given type as a msgpack Value
pub fn pack(comptime T: type, writer: std.io.AnyWriter) anyerror!void {}

/// Unpack the next msgpack Value from reader as type T
pub fn unpack(comptime T: type, reader: std.io.AnyReader) anyerror!void {}
```

For packing, any type which has a function signature `msgpackPack(self: T,
writer: std.io.AnyWriter) anyerror!void` will use this function has for packing.
Otherwise it will be packed using the defaults.

Likewise, unpacking types can implement `msgpackUnpack(writer: std.io.AnyWriter) anyerror!T` to unpack from a stream, or `msgpackUnpackFromValue(value: msgpack.Value) anyerror!T` to unpack from a msgpack.Value.

## Value

msgpack values are stored internally as a tagged union. Note that we impose a
limitation on maps: the keys *must* be strings, similar to JSON (the msgpack
specification allows for any msgpack type to be a key).

```zig
pub const Value = union(enum) {
    i64: i64,
    u64: u64,
    f64: f64,
    nil: void,
    bool: bool,
    str: []const u8,
    bin: []const u8,
    array: []Value,
    map: std.StringHashMap(Value),
    ext: struct {
        id: i8,
        data: []const u8,
    },
};
```

## Roadmap

- [ ] Automatic unpacking of `map` to structs
