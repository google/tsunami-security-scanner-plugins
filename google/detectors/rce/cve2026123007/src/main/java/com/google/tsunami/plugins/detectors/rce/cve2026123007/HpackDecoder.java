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
package com.google.tsunami.plugins.detectors.rce.cve2026123007;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.collect.ImmutableList;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Clean-room RFC 7541 HPACK header block decoder (Appendix A static table, bounded dynamic table,
 * and Appendix B canonical Huffman decoding) for HTTP/2 response header verification.
 */
final class HpackDecoder {
  static final int MAX_HEADER_TABLE_SIZE = 4096;
  private static final int MAX_STRING_BYTES = 8192;
  private static final int MAX_INTEGER_VALUE = 1_000_000;
  private static final int EOS_SYMBOL = 256;
  private static final int EOS_CODE = 0x3fffffff;
  private static final int EOS_BITS = 30;

  record HeaderField(String name, String value) {
    private int hpackSize() {
      return name.length() + value.length() + 32;
    }
  }

  static final class HpackException extends Exception {
    HpackException(String message) {
      super(message);
    }
  }

  private static final ImmutableList<HeaderField> STATIC_TABLE =
      ImmutableList.of(
          new HeaderField("", ""),
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
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
  };

  private static final int[] huffmanCodeLengths = {
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
  };

  private static final class HuffmanNode {
    int symbol = -1; // NOMUTANTS -- negative sentinel for internal trie node
    HuffmanNode left;
    HuffmanNode right;
  }

  private static final HuffmanNode HUFFMAN_ROOT = buildHuffmanTrie();

  private final List<HeaderField> dynamicTable = new ArrayList<>();
  private int dynamicTableSize = 0;
  private int maxDynamicTableSize = MAX_HEADER_TABLE_SIZE;

  ImmutableList<HeaderField> decode(byte[] block) throws HpackException {
    ImmutableList.Builder<HeaderField> out = ImmutableList.builder();
    Cursor cursor = new Cursor(block);
    boolean seenHeaderField = false;

    while (cursor.hasRemaining()) {
      int first = cursor.peekByte();
      if ((first & 0x80) != 0) {
        seenHeaderField = true;
        int index = readPrefixedInt(cursor, 7);
        if (index == 0) {
          throw new HpackException("Invalid indexed header field index 0.");
        }
        out.add(lookupIndex(index));
      } else if ((first & 0xc0) == 0x40) {
        seenHeaderField = true;
        HeaderField hf = readLiteralHeaderField(cursor, 6);
        addToDynamicTable(hf);
        out.add(hf);
      } else if ((first & 0xe0) == 0x20) {
        if (seenHeaderField) {
          throw new HpackException("Dynamic table size update after header emission.");
        }
        int newMaxSize = readPrefixedInt(cursor, 5);
        if (newMaxSize > MAX_HEADER_TABLE_SIZE) {
          throw new HpackException("Dynamic table size update exceeds SETTINGS limit.");
        }
        this.maxDynamicTableSize = newMaxSize;
        evictToSize(newMaxSize);
      } else {
        seenHeaderField = true;
        out.add(readLiteralHeaderField(cursor, 4));
      }
    }
    return out.build();
  }

  private static HuffmanNode buildHuffmanTrie() {
    HuffmanNode root = new HuffmanNode();
    for (int sym = 0; sym < huffmanCodes.length; sym++) {
      insertCode(root, huffmanCodes[sym], huffmanCodeLengths[sym], sym);
    }
    insertCode(root, EOS_CODE, EOS_BITS, EOS_SYMBOL);
    return root;
  }

  private static void insertCode(HuffmanNode root, int code, int bitLen, int symbol) {
    HuffmanNode cur = root;
    for (int i = bitLen - 1; i >= 0; i--) {
      int bit = (code >>> i) & 1;
      if (bit == 0) {
        if (cur.left == null) {
          cur.left = new HuffmanNode();
        }
        cur = cur.left;
      } else {
        if (cur.right == null) {
          cur.right = new HuffmanNode();
        }
        cur = cur.right;
      }
    }
    cur.symbol = symbol;
  }

  private HeaderField readLiteralHeaderField(Cursor cursor, int namePrefixBits)
      throws HpackException {
    int nameIndex = readPrefixedInt(cursor, namePrefixBits);
    String name = (nameIndex == 0) ? readString(cursor) : lookupIndex(nameIndex).name();
    String value = readString(cursor);
    return new HeaderField(name, value);
  }

  private HeaderField lookupIndex(int index) throws HpackException {
    int staticCount = STATIC_TABLE.size() - 1;
    if (index <= staticCount) {
      return STATIC_TABLE.get(index);
    }
    int dynOffset = index - staticCount - 1;
    if (dynOffset >= dynamicTable.size()) {
      throw new HpackException("Header table index out of bounds: " + index);
    }
    return dynamicTable.get(dynOffset);
  }

  private void addToDynamicTable(HeaderField field) {
    int entrySize = field.hpackSize();
    if (entrySize > maxDynamicTableSize) {
      dynamicTable.clear();
      dynamicTableSize = 0;
      return;
    }
    evictToSize(maxDynamicTableSize - entrySize);
    dynamicTable.add(0, field);
    dynamicTableSize += entrySize;
  }

  private void evictToSize(int targetSize) {
    while (dynamicTableSize > targetSize) {
      HeaderField removed = dynamicTable.remove(dynamicTable.size() - 1);
      dynamicTableSize -= removed.hpackSize();
    }
  }

  private static int readPrefixedInt(Cursor cursor, int prefixBits) throws HpackException {
    int mask = (1 << prefixBits) - 1;
    int value = cursor.nextByte() & mask;
    if (value < mask) {
      return value;
    }
    int shift = 0;
    while (true) {
      if (!cursor.hasRemaining()) {
        throw new HpackException("Truncated multi-byte HPACK integer.");
      }
      if (shift > 28) {
        throw new HpackException("HPACK integer shift overflow.");
      }
      int b = cursor.nextByte();
      long addend = (long) (b & 0x7f) << shift;
      if (value + addend > MAX_INTEGER_VALUE) {
        throw new HpackException("HPACK integer exceeds maximum limit.");
      }
      value += (int) addend;
      if ((b & 0x80) == 0) {
        return value;
      }
      shift += 7;
    }
  }

  private static String readString(Cursor cursor) throws HpackException {
    if (!cursor.hasRemaining()) {
      throw new HpackException("Unexpected EOF reading HPACK string header.");
    }
    boolean huffman = (cursor.peekByte() & 0x80) != 0;
    int length = readPrefixedInt(cursor, 7);
    if (length > MAX_STRING_BYTES) {
      throw new HpackException("HPACK string exceeds maximum allowed length.");
    }
    byte[] raw = cursor.nextBytes(length);
    if (!huffman) {
      return new String(raw, ISO_8859_1);
    }
    byte[] decoded = decodeHuffman(raw);
    return new String(decoded, ISO_8859_1);
  }

  private static byte[] decodeHuffman(byte[] encoded) throws HpackException {
    ByteArrayOutputStream out =
        new ByteArrayOutputStream(encoded.length * 2); // NOMUTANTS -- buffer preallocation hint
    HuffmanNode node = HUFFMAN_ROOT;
    int currentBits = 0;
    int currentValue = 0;

    for (byte b : encoded) {
      int unsigned = b & 0xff;
      for (int bitIdx = 7; bitIdx >= 0; bitIdx--) {
        int bit = (unsigned >>> bitIdx) & 1;
        node = (bit == 0) ? node.left : node.right;
        if (node == null) {
          throw new HpackException("Invalid Huffman bit sequence.");
        }
        currentBits++;
        currentValue = (currentValue << 1) | bit;
        if (node.symbol >= 0) {
          if (node.symbol == EOS_SYMBOL) {
            throw new HpackException("Huffman string contains explicit EOS symbol.");
          }
          if (out.size() >= MAX_STRING_BYTES) {
            throw new HpackException("Decoded Huffman string exceeds maximum allowed length.");
          }
          out.write(node.symbol);
          node = HUFFMAN_ROOT;
          currentBits = 0;
          currentValue = 0;
        }
      }
    }

    if (currentBits > 7) {
      throw new HpackException("Huffman trailing padding exceeds 7 bits.");
    }
    int expectedPadding = (1 << currentBits) - 1;
    if (currentValue != expectedPadding) {
      throw new HpackException("Huffman trailing padding is not all-ones EOS prefix.");
    }
    return out.toByteArray();
  }

  private static final class Cursor {
    private final byte[] data;
    private int pos = 0;

    Cursor(byte[] data) {
      this.data = data;
    }

    boolean hasRemaining() {
      return pos < data.length;
    }

    int peekByte() {
      return data[pos] & 0xff;
    }

    int nextByte() {
      return data[pos++] & 0xff;
    }

    byte[] nextBytes(int len) throws HpackException {
      if (len < 0 || pos + len > data.length) {
        throw new HpackException("Truncated HPACK string literal.");
      }
      byte[] slice = new byte[len];
      System.arraycopy(data, pos, slice, 0, len);
      pos += len;
      return slice;
    }
  }
}
