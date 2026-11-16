/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.cve2026119618;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Bounded RFC 7541 HPACK header encoder and decoder (including static table 1..61, connection-level
 * FIFO dynamic table with 32-octet entry overhead, bounded varints, and RFC 7541 Appendix B Huffman
 * decoding with strict EOS and padding validation).
 */
final class HpackCodec {

  static final int DEFAULT_DYNAMIC_TABLE_SIZE = 4096;
  static final int MAX_STRING_LENGTH = 8192;
  static final int MAX_HEADER_FIELDS = 128;
  private static final int ENTRY_OVERHEAD_BYTES = 32;
  private static final int MAX_VARINT_CONTINUATION_BYTES = 5;
  private static final int HUFFMAN_EOS_SYMBOL = 256;

  private HpackCodec() {}

  static final class HeaderField {
    final String name;
    final String value;

    HeaderField(String name, String value) {
      this.name = name;
      this.value = value;
    }

    int entrySize() {
      return name.length() + value.length() + ENTRY_OVERHEAD_BYTES;
    }
  }

  /** Encodes outbound HTTP/2 request headers using literal never-indexed representations. */
  static byte[] encodeLiteralNeverIndexed(List<HeaderField> headers) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (HeaderField hf : headers) {
      out.write(0x10); // Literal Header Field Never Indexed, new name (index 0)
      byte[] nameBytes = hf.name.getBytes(ISO_8859_1);
      writeVarInt(out, nameBytes.length, 7, 0x00);
      out.writeBytes(nameBytes);
      byte[] valueBytes = hf.value.getBytes(ISO_8859_1);
      writeVarInt(out, valueBytes.length, 7, 0x00);
      out.writeBytes(valueBytes);
    }
    return out.toByteArray();
  }

  static void writeVarInt(ByteArrayOutputStream out, int value, int prefixBits, int firstByteMask) {
    int maxPrefix = (1 << prefixBits) - 1;
    if (value < maxPrefix) {
      out.write(firstByteMask | value);
      return;
    }
    out.write(firstByteMask | maxPrefix);
    int rem = value - maxPrefix;
    while (rem >= 128) {
      out.write((rem & 0x7f) | 0x80);
      rem >>>= 7;
    }
    out.write(rem);
  }

  /**
   * Connection-scoped RFC 7541 HPACK decoder. One instance must be bound 1:1 to each HTTP/2
   * connection so {@code nghttp2} dynamic table insertions on Stream 1 resolve on Streams 3 and 5.
   */
  static final class Decoder {
    private final int maxAllowedTableSize;
    private int currentMaxTableSize;
    private int currentTableBytes;
    // Newest entry at head (index 62), oldest entry at tail (FIFO eviction).
    private final Deque<HeaderField> dynamicTable = new ArrayDeque<>();

    Decoder(int maxAllowedTableSize) {
      this.maxAllowedTableSize = maxAllowedTableSize;
      this.currentMaxTableSize = maxAllowedTableSize;
    }

    ImmutableList<HeaderField> decodeHeaderBlock(byte[] block) throws IOException {
      ByteCursor cursor = new ByteCursor(block);
      ImmutableList.Builder<HeaderField> fields = ImmutableList.builder();
      int count = 0;
      boolean seenHeaderField = false;

      while (cursor.hasRemaining()) {
        int b = cursor.peekUnsignedByte();
        if ((b & 0x80) != 0) {
          // 6.1 Indexed Header Field Representation (prefix 7)
          seenHeaderField = true;
          int idx = readVarInt(cursor, 7);
          if (idx <= 0) {
            throw new IOException("Invalid HPACK index 0");
          }
          fields.add(lookupIndex(idx));
          count = checkFieldCount(count);
        } else if ((b & 0x40) != 0) {
          // 6.2.1 Literal Header Field with Incremental Indexing (prefix 6)
          seenHeaderField = true;
          int nameIdx = readVarInt(cursor, 6);
          String name = nameIdx == 0 ? readString(cursor) : lookupIndex(nameIdx).name;
          String value = readString(cursor);
          HeaderField entry = new HeaderField(name, value);
          insertDynamicEntry(entry);
          fields.add(entry);
          count = checkFieldCount(count);
        } else if ((b & 0x20) != 0) {
          // 6.3 Dynamic Table Size Update (prefix 5) — only legal before header fields in block
          if (seenHeaderField) {
            throw new IOException("HPACK dynamic table size update after header field");
          }
          int newMax = readVarInt(cursor, 5);
          if (newMax > maxAllowedTableSize) {
            throw new IOException("HPACK dynamic table size exceeds allowed limit: " + newMax);
          }
          currentMaxTableSize = newMax;
          evictToSize(currentMaxTableSize);
        } else {
          // 6.2.2 / 6.2.3 Literal Header Field without Indexing or Never Indexed (prefix 4)
          seenHeaderField = true;
          int nameIdx = readVarInt(cursor, 4);
          String name = nameIdx == 0 ? readString(cursor) : lookupIndex(nameIdx).name;
          String value = readString(cursor);
          fields.add(new HeaderField(name, value));
          count = checkFieldCount(count);
        }
      }

      return fields.build();
    }

    private static int checkFieldCount(int current) throws IOException {
      int next = current + 1;
      if (next > MAX_HEADER_FIELDS) {
        throw new IOException("Exceeded maximum HPACK header count");
      }
      return next;
    }

    private HeaderField lookupIndex(int index) throws IOException {
      if (index <= STATIC_TABLE.size()) {
        return STATIC_TABLE.get(index - 1);
      }
      int dynOffset = index - STATIC_TABLE.size() - 1;
      if (dynOffset >= dynamicTable.size()) {
        throw new IOException("HPACK index out of bounds: " + index);
      }
      Iterator<HeaderField> it = dynamicTable.iterator();
      Iterators.advance(it, dynOffset);
      return it.next();
    }

    private void insertDynamicEntry(HeaderField entry) {
      int entryBytes = entry.entrySize();
      if (entryBytes > currentMaxTableSize) {
        evictToSize(0);
        return;
      }
      evictToSize(currentMaxTableSize - entryBytes);
      dynamicTable.addFirst(entry);
      currentTableBytes += entryBytes;
    }

    private void evictToSize(int targetBytes) {
      while (currentTableBytes > targetBytes && !dynamicTable.isEmpty()) {
        HeaderField removed = dynamicTable.removeLast();
        currentTableBytes -= removed.entrySize();
      }
    }
  }

  static int readVarInt(ByteCursor cursor, int prefixBits) throws IOException {
    int first = cursor.readUnsignedByte();
    int maxPrefix = (1 << prefixBits) - 1;
    int value = first & maxPrefix;
    if (value < maxPrefix) {
      return value;
    }
    int shift = 0;
    for (int i = 0; i < MAX_VARINT_CONTINUATION_BYTES; i++) {
      int b = cursor.readUnsignedByte();
      long addend = (long) (b & 0x7f) << shift;
      if (value + addend > Integer.MAX_VALUE) {
        throw new IOException("HPACK integer overflow");
      }
      value += (int) addend;
      if ((b & 0x80) == 0) {
        return value;
      }
      shift += 7;
    }
    throw new IOException("HPACK varint exceeds maximum continuation bytes");
  }

  static String readString(ByteCursor cursor) throws IOException {
    int first = cursor.peekUnsignedByte();
    boolean huffman = (first & 0x80) != 0;
    int byteLen = readVarInt(cursor, 7);
    if (byteLen > MAX_STRING_LENGTH) {
      throw new IOException("HPACK string exceeds maximum length: " + byteLen);
    }
    byte[] raw = cursor.readBytes(byteLen);
    if (!huffman) {
      return new String(raw, ISO_8859_1);
    }
    byte[] decoded = decodeHuffman(raw);
    if (decoded.length > MAX_STRING_LENGTH) {
      throw new IOException("Decoded Huffman string exceeds maximum length");
    }
    return new String(decoded, ISO_8859_1);
  }

  static byte[] decodeHuffman(byte[] data) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    HuffmanNode node = HUFFMAN_ROOT;
    int bitCount = 0;

    for (byte rawByte : data) {
      int unsigned = rawByte & 0xff;
      for (int bitIdx = 7; bitIdx >= 0; bitIdx--) {
        int bit = (unsigned >>> bitIdx) & 1;
        node = bit == 0 ? node.left : node.right;
        bitCount++;
        if (node.left == null) {
          if (node.symbol == HUFFMAN_EOS_SYMBOL) {
            throw new IOException("Illegal Huffman EOS symbol in string literal");
          }
          out.write(node.symbol);
          node = HUFFMAN_ROOT;
          bitCount = 0;
        }
      }
    }

    if (bitCount > 7) {
      throw new IOException("Huffman trailing padding exceeds 7 bits");
    }
    if (bitCount > 0) {
      int expectedOnes = (1 << bitCount) - 1;
      if ((data[data.length - 1] & expectedOnes) != expectedOnes) {
        throw new IOException("Huffman trailing padding bits are not all ones");
      }
    }
    return out.toByteArray();
  }

  static final class ByteCursor {
    private final byte[] buf;
    private int pos;

    ByteCursor(byte[] buf) {
      this.buf = buf;
    }

    boolean hasRemaining() {
      return pos < buf.length;
    }

    int peekUnsignedByte() throws IOException {
      if (pos >= buf.length) {
        throw new IOException("Unexpected end of HPACK block");
      }
      return buf[pos] & 0xff;
    }

    int readUnsignedByte() throws IOException {
      if (pos >= buf.length) {
        throw new IOException("Unexpected end of HPACK block");
      }
      return buf[pos++] & 0xff;
    }

    byte[] readBytes(int length) throws IOException {
      if (length < 0 || pos + length > buf.length) {
        throw new IOException("Truncated HPACK string payload");
      }
      byte[] slice = new byte[length];
      System.arraycopy(buf, pos, slice, 0, length);
      pos += length;
      return slice;
    }
  }

  private static final class HuffmanNode {
    HuffmanNode left;
    HuffmanNode right;
    int symbol;
  }

  private static final ImmutableList<HeaderField> STATIC_TABLE =
      ImmutableList.of(
          new HeaderField(":authority", ""),
          new HeaderField(":method", "GET"),
          new HeaderField(":method", "POST"),
          new HeaderField(":path", "/"),
          new HeaderField(":path", "/index.html"),
          new HeaderField(":scheme", "http"),
          new HeaderField(":scheme", "https"),
          new HeaderField(":status", "200"),
          new HeaderField(":status", "204"),
          new HeaderField(":status", "206"),
          new HeaderField(":status", "304"),
          new HeaderField(":status", "400"),
          new HeaderField(":status", "404"),
          new HeaderField(":status", "500"),
          new HeaderField("accept-charset", ""),
          new HeaderField("accept-encoding", "gzip, deflate"),
          new HeaderField("accept-language", ""),
          new HeaderField("accept-ranges", ""),
          new HeaderField("accept", ""),
          new HeaderField("access-control-allow-origin", ""),
          new HeaderField("age", ""),
          new HeaderField("allow", ""),
          new HeaderField("authorization", ""),
          new HeaderField("cache-control", ""),
          new HeaderField("content-disposition", ""),
          new HeaderField("content-encoding", ""),
          new HeaderField("content-language", ""),
          new HeaderField("content-length", ""),
          new HeaderField("content-location", ""),
          new HeaderField("content-range", ""),
          new HeaderField("content-type", ""),
          new HeaderField("cookie", ""),
          new HeaderField("date", ""),
          new HeaderField("etag", ""),
          new HeaderField("expect", ""),
          new HeaderField("expires", ""),
          new HeaderField("from", ""),
          new HeaderField("host", ""),
          new HeaderField("if-match", ""),
          new HeaderField("if-modified-since", ""),
          new HeaderField("if-none-match", ""),
          new HeaderField("if-range", ""),
          new HeaderField("if-unmodified-since", ""),
          new HeaderField("last-modified", ""),
          new HeaderField("link", ""),
          new HeaderField("location", ""),
          new HeaderField("max-forwards", ""),
          new HeaderField("proxy-authenticate", ""),
          new HeaderField("proxy-authorization", ""),
          new HeaderField("range", ""),
          new HeaderField("referer", ""),
          new HeaderField("refresh", ""),
          new HeaderField("retry-after", ""),
          new HeaderField("server", ""),
          new HeaderField("set-cookie", ""),
          new HeaderField("strict-transport-security", ""),
          new HeaderField("transfer-encoding", ""),
          new HeaderField("user-agent", ""),
          new HeaderField("vary", ""),
          new HeaderField("via", ""),
          new HeaderField("www-authenticate", ""));

  private static final int[] huffmanCodes = {
    0x1ff8,
    0x7fffd8,
    0xfffffe2,
    0xfffffe3,
    0xfffffe4,
    0xfffffe5,
    0xfffffe6,
    0xfffffe7,
    0xfffffe8,
    0xffffea,
    0x3ffffffc,
    0xfffffe9,
    0xfffffea,
    0x3ffffffd,
    0xfffffeb,
    0xfffffec,
    0xfffffed,
    0xfffffee,
    0xfffffef,
    0xffffff0,
    0xffffff1,
    0xffffff2,
    0x3ffffffe,
    0xffffff3,
    0xffffff4,
    0xffffff5,
    0xffffff6,
    0xffffff7,
    0xffffff8,
    0xffffff9,
    0xffffffa,
    0xffffffb,
    0x14,
    0x3f8,
    0x3f9,
    0xffa,
    0x1ff9,
    0x15,
    0xf8,
    0x7fa,
    0x3fa,
    0x3fb,
    0xf9,
    0x7fb,
    0xfa,
    0x16,
    0x17,
    0x18,
    0x0,
    0x1,
    0x2,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x5c,
    0xfb,
    0x7ffc,
    0x20,
    0xffb,
    0x3fc,
    0x1ffa,
    0x21,
    0x5d,
    0x5e,
    0x5f,
    0x60,
    0x61,
    0x62,
    0x63,
    0x64,
    0x65,
    0x66,
    0x67,
    0x68,
    0x69,
    0x6a,
    0x6b,
    0x6c,
    0x6d,
    0x6e,
    0x6f,
    0x70,
    0x71,
    0x72,
    0xfc,
    0x73,
    0xfd,
    0x1ffb,
    0x7fff0,
    0x1ffc,
    0x3ffc,
    0x22,
    0x7ffd,
    0x3,
    0x23,
    0x4,
    0x24,
    0x5,
    0x25,
    0x26,
    0x27,
    0x6,
    0x74,
    0x75,
    0x28,
    0x29,
    0x2a,
    0x7,
    0x2b,
    0x76,
    0x2c,
    0x8,
    0x9,
    0x2d,
    0x77,
    0x78,
    0x79,
    0x7a,
    0x7b,
    0x7ffe,
    0x7fc,
    0x3ffd,
    0x1ffd,
    0xffffffc,
    0xfffe6,
    0x3fffd2,
    0xfffe7,
    0xfffe8,
    0x3fffd3,
    0x3fffd4,
    0x3fffd5,
    0x7fffd9,
    0x3fffd6,
    0x7fffda,
    0x7fffdb,
    0x7fffdc,
    0x7fffdd,
    0x7fffde,
    0xffffeb,
    0x7fffdf,
    0xffffec,
    0xffffed,
    0x3fffd7,
    0x7fffe0,
    0xffffee,
    0x7fffe1,
    0x7fffe2,
    0x7fffe3,
    0x7fffe4,
    0x1fffdc,
    0x3fffd8,
    0x7fffe5,
    0x3fffd9,
    0x7fffe6,
    0x7fffe7,
    0xffffef,
    0x3fffda,
    0x1fffdd,
    0xfffe9,
    0x3fffdb,
    0x3fffdc,
    0x7fffe8,
    0x7fffe9,
    0x1fffde,
    0x7fffea,
    0x3fffdd,
    0x3fffde,
    0xfffff0,
    0x1fffdf,
    0x3fffdf,
    0x7fffeb,
    0x7fffec,
    0x1fffe0,
    0x1fffe1,
    0x3fffe0,
    0x1fffe2,
    0x7fffed,
    0x3fffe1,
    0x7fffee,
    0x7fffef,
    0xfffea,
    0x3fffe2,
    0x3fffe3,
    0x3fffe4,
    0x7ffff0,
    0x3fffe5,
    0x3fffe6,
    0x7ffff1,
    0x3ffffe0,
    0x3ffffe1,
    0xfffeb,
    0x7fff1,
    0x3fffe7,
    0x7ffff2,
    0x3fffe8,
    0x1ffffec,
    0x3ffffe2,
    0x3ffffe3,
    0x3ffffe4,
    0x7ffffde,
    0x7ffffdf,
    0x3ffffe5,
    0xfffff1,
    0x1ffffed,
    0x7fff2,
    0x1fffe3,
    0x3ffffe6,
    0x7ffffe0,
    0x7ffffe1,
    0x3ffffe7,
    0x7ffffe2,
    0xfffff2,
    0x1fffe4,
    0x1fffe5,
    0x3ffffe8,
    0x3ffffe9,
    0xffffffd,
    0x7ffffe3,
    0x7ffffe4,
    0x7ffffe5,
    0xfffec,
    0xfffff3,
    0xfffed,
    0x1fffe6,
    0x3fffe9,
    0x1fffe7,
    0x1fffe8,
    0x7ffff3,
    0x3fffea,
    0x3fffeb,
    0x1ffffee,
    0x1ffffef,
    0xfffff4,
    0xfffff5,
    0x3ffffea,
    0x7ffff4,
    0x3ffffeb,
    0x7ffffe6,
    0x3ffffec,
    0x3ffffed,
    0x7ffffe7,
    0x7ffffe8,
    0x7ffffe9,
    0x7ffffea,
    0x7ffffeb,
    0xffffffe,
    0x7ffffec,
    0x7ffffed,
    0x7ffffee,
    0x7ffffef,
    0x7fffff0,
    0x3ffffee,
    0x3fffffff
  };

  private static final int[] huffmanCodeLens = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30
  };

  private static final HuffmanNode HUFFMAN_ROOT = buildHuffmanTree();

  private static HuffmanNode buildHuffmanTree() {
    HuffmanNode root = new HuffmanNode();
    for (int sym = 0; sym < huffmanCodes.length; sym++) {
      int code = huffmanCodes[sym];
      int len = huffmanCodeLens[sym];
      HuffmanNode curr = root;
      for (int bitIdx = len - 1; bitIdx >= 0; bitIdx--) {
        int bit = (code >>> bitIdx) & 1;
        if (bit == 0) {
          if (curr.left == null) {
            curr.left = new HuffmanNode();
          }
          curr = curr.left;
        } else {
          if (curr.right == null) {
            curr.right = new HuffmanNode();
          }
          curr = curr.right;
        }
      }
      curr.symbol = sym;
    }
    return root;
  }
}
