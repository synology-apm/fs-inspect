# Codec test data

Compressed streams the decoders must read back exactly, most of them made by the compression
tools of other systems.

| Files | Made by | Checked by |
|---|---|---|
| `*.lzo`, `*.9.lzo` | `lzop -1` and `lzop -9` (lzop 1.04, Ubuntu, in the `fsi-tools-vm` Docker image) from four inputs: text, a mix of runs, repeats and noise, 70000 zero bytes, and noise | `tests/lzo_files.rs`, against the Adler-32 of its decompressed bytes lzop stores in each block (so the inputs are not kept) |
| `*.cab`, `cab-expected.txt` | Windows' `makecab /D CompressionType=LZX /D CompressionMemory=15` (LZX with a 32 KiB window, as WOF uses) from text, a mix of runs, repeats, `E8` call instructions and noise (32000 and 300000 bytes), and noise | `tests/lzx_cabinets.rs`, against each input's size and SHA-256 in `cab-expected.txt` |
| `lz4/*.lz4`, `lzbitmap/apple-*.zbm` | macOS's libcompression | `tests/apple_streams.rs`, against the digest and length in the input's `.sha256` file |
| `lzbitmap/mine-*.zbm` | written for these tests, one per LZBITMAP header variant (16 and 32 KiB chunks, tokens run-length coded or not); macOS's libcompression decodes each to the bytes of its `.sha256` line | `tests/apple_streams.rs`, as above |

`tests/apple_streams.rs` also decodes every stream into a smaller buffer (the same first bytes)
and cut short or damaged (never a panic).
