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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.HpackCodec.ByteCursor;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.HpackCodec.HeaderField;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpackCodec}. */
@RunWith(JUnit4.class)
public final class HpackCodecTest {

  @Test
  public void encodeLiteralNeverIndexed_roundTripsIncludingMultiByteVarintLengths()
      throws IOException {
    String longVal = "v".repeat(200);
    ImmutableList<HeaderField> original =
        ImmutableList.of(
            new HeaderField(":method", "TRACE"),
            new HeaderField("content-type", "text/plain"),
            new HeaderField("x-tsunami-probe", longVal));

    byte[] encoded = HpackCodec.encodeLiteralNeverIndexed(original);
    HpackCodec.Decoder decoder = new HpackCodec.Decoder(HpackCodec.DEFAULT_DYNAMIC_TABLE_SIZE);
    ImmutableList<HeaderField> decoded = decoder.decodeHeaderBlock(encoded);

    assertThat(decoded).hasSize(3);
    assertThat(decoded.get(0).name).isEqualTo(":method");
    assertThat(decoded.get(0).value).isEqualTo("TRACE");
    assertThat(decoded.get(1).name).isEqualTo("content-type");
    assertThat(decoded.get(1).value).isEqualTo("text/plain");
    assertThat(decoded.get(2).name).isEqualTo("x-tsunami-probe");
    assertThat(decoded.get(2).value).isEqualTo(longVal);
    // Literal Never Indexed must NOT insert into dynamic table (index 62 must be out of bounds).
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe}));
  }

  @Test
  public void decoder_maintainsConnectionDynamicTableAndFifoEvictionWith32ByteOverhead()
      throws IOException {
    // Allow 108 bytes: each entry "k1"="v1" costs 2 + 2 + 32 = 36 bytes -> exact fit for 3 entries
    // (3 * 36 = 108).
    HpackCodec.Decoder decoder = new HpackCodec.Decoder(108);

    // Block 1: insert (k1,v1), (k2,v2), (k3,v3) via Literal with Incremental Indexing (0x40).
    ByteArrayOutputStream block1 = new ByteArrayOutputStream();
    writeIncrementalLiteral(block1, "k1", "v1");
    writeIncrementalLiteral(block1, "k2", "v2");
    writeIncrementalLiteral(block1, "k3", "v3");
    ImmutableList<HeaderField> first = decoder.decodeHeaderBlock(block1.toByteArray());
    assertThat(first).hasSize(3);

    // Newest is at index 62 (k3), oldest at index 64 (k1).
    ImmutableList<HeaderField> lookupBeforeEvict =
        decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe, (byte) 0xbf, (byte) 0xc0});
    assertThat(lookupBeforeEvict.get(0).name).isEqualTo("k3");
    assertThat(lookupBeforeEvict.get(1).name).isEqualTo("k2");
    assertThat(lookupBeforeEvict.get(2).name).isEqualTo("k1");

    // Insert (k4,v4) -> evicts oldest (k1); index 64 is now k2, and index 65 is out of bounds.
    ByteArrayOutputStream block2 = new ByteArrayOutputStream();
    writeIncrementalLiteral(block2, "k4", "v4");
    assertThat(decoder.decodeHeaderBlock(block2.toByteArray())).hasSize(1);

    ImmutableList<HeaderField> lookupAfterEvict =
        decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe, (byte) 0xc0});
    assertThat(lookupAfterEvict.get(0).name).isEqualTo("k4");
    assertThat(lookupAfterEvict.get(1).name).isEqualTo("k2");
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0xc1}));

    // Entry larger than max table size clears dynamic table cleanly per RFC 7541 Section 4.4
    // and resets currentTableBytes to 0 so subsequent entries fit without premature eviction.
    ByteArrayOutputStream oversizedEntry = new ByteArrayOutputStream();
    writeIncrementalLiteral(oversizedEntry, "big-key", "x".repeat(100));
    ImmutableList<HeaderField> oversizedDecoded =
        decoder.decodeHeaderBlock(oversizedEntry.toByteArray());
    assertThat(oversizedDecoded).hasSize(1);
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe}));

    ByteArrayOutputStream afterClear = new ByteArrayOutputStream();
    writeIncrementalLiteral(afterClear, "k5", "v5");
    writeIncrementalLiteral(afterClear, "k6", "v6");
    assertThat(decoder.decodeHeaderBlock(afterClear.toByteArray())).hasSize(2);
    ImmutableList<HeaderField> lookupAfterClear =
        decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe, (byte) 0xbf});
    assertThat(lookupAfterClear.get(0).name).isEqualTo("k6");
    assertThat(lookupAfterClear.get(1).name).isEqualTo("k5");
  }

  @Test
  public void decoder_enforcesDynamicTableSizeUpdateRules() throws IOException {
    HpackCodec.Decoder decoder = new HpackCodec.Decoder(256);
    ByteArrayOutputStream seed = new ByteArrayOutputStream();
    writeIncrementalLiteral(seed, "custom", "val");
    assertThat(decoder.decodeHeaderBlock(seed.toByteArray())).hasSize(1);

    // Valid size update to 0 followed by restore to 128 at start of block evicts prior entries.
    byte[] validUpdates =
        new byte[] {0x20, 0x3f, 0x61, (byte) 0x88}; // size=0, size=128, :status=200
    ImmutableList<HeaderField> res = decoder.decodeHeaderBlock(validUpdates);
    assertThat(res).hasSize(1);
    assertThat(res.get(0).value).isEqualTo("200");
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0xbe}));

    // Size update after a header field in the same block is a protocol error.
    IOException afterHeader =
        assertThrows(
            IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0x88, 0x20}));
    assertThat(afterHeader).hasMessageThat().contains("after header field");

    // Size update exceeding maxAllowedTableSize (256) is rejected.
    ByteArrayOutputStream tooBigUpdate = new ByteArrayOutputStream();
    HpackCodec.writeVarInt(tooBigUpdate, 512, 5, 0x20);
    IOException exceedsMax =
        assertThrows(
            IOException.class, () -> decoder.decodeHeaderBlock(tooBigUpdate.toByteArray()));
    assertThat(exceedsMax).hasMessageThat().contains("exceeds allowed limit");
  }

  @Test
  public void decodeHuffman_decodesRfc7541VectorsAndRejectsEosAndInvalidPadding()
      throws IOException {
    // RFC 7541 Appendix C.4.1 - C.4.3 Huffman test vectors.
    byte[] wwwExample = BaseEncoding.base16().lowerCase().decode("f1e3c2e5f23a6ba0ab90f4ff");
    assertThat(new String(HpackCodec.decodeHuffman(wwwExample), ISO_8859_1))
        .isEqualTo("www.example.com");

    byte[] noCache = BaseEncoding.base16().lowerCase().decode("a8eb10649cbf");
    assertThat(new String(HpackCodec.decodeHuffman(noCache), ISO_8859_1)).isEqualTo("no-cache");

    byte[] customKey = BaseEncoding.base16().lowerCase().decode("25a849e95ba97d7f");
    assertThat(new String(HpackCodec.decodeHuffman(customKey), ISO_8859_1)).isEqualTo("custom-key");

    byte[] customVal = BaseEncoding.base16().lowerCase().decode("25a849e95bb8e8b4bf");
    assertThat(new String(HpackCodec.decodeHuffman(customVal), ISO_8859_1))
        .isEqualTo("custom-value");

    assertThat(HpackCodec.decodeHuffman(new byte[0])).isEmpty();

    // 30-bit EOS symbol (all ones) inside literal must fail.
    IOException eosErr =
        assertThrows(
            IOException.class,
            () ->
                HpackCodec.decodeHuffman(
                    new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}));
    assertThat(eosErr).hasMessageThat().contains("EOS");

    // >7-bit trailing padding (appending 0xff to byte-aligned "www.example.com") must fail.
    byte[] overPadded = BaseEncoding.base16().lowerCase().decode("f1e3c2e5f23a6ba0ab90f4ffff");
    IOException padLenErr =
        assertThrows(IOException.class, () -> HpackCodec.decodeHuffman(overPadded));
    assertThat(padLenErr).hasMessageThat().contains("7 bits");

    // Non-1 trailing padding bit (changing 0xbf -> 0xbe and 0xbf -> 0x9f on "no-cache") must fail,
    // and symbol 0 ('\0', 0x1ff8) + sibling symbol 36 ('$', 0x1ff9) must decode accurately.
    assertThat(HpackCodec.decodeHuffman(new byte[] {(byte) 0xff, (byte) 0xc7}))
        .isEqualTo(new byte[] {0});
    assertThat(HpackCodec.decodeHuffman(new byte[] {(byte) 0xff, (byte) 0xcf}))
        .isEqualTo(new byte[] {'$'});
    byte[] zeroPad = BaseEncoding.base16().lowerCase().decode("a8eb10649cbe");
    IOException nonOneErr =
        assertThrows(IOException.class, () -> HpackCodec.decodeHuffman(zeroPad));
    assertThat(nonOneErr).hasMessageThat().contains("all ones");
    assertThrows(IOException.class, () -> HpackCodec.decodeHuffman(new byte[] {0x01}));
  }

  @Test
  public void readVarIntAndLimits_rejectOverflowTruncatedAndOversizedBlocks() {
    // Index 0 in Indexed Header Field (0x80) is illegal.
    HpackCodec.Decoder decoder = new HpackCodec.Decoder(4096);
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(new byte[] {(byte) 0x80}));

    // Integer overflow in varint continuation shift.
    byte[] overflowVarint =
        new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f};
    IOException overflow =
        assertThrows(
            IOException.class, () -> HpackCodec.readVarInt(new ByteCursor(overflowVarint), 7));
    assertThat(overflow).hasMessageThat().contains("overflow");

    // Excessive continuation bytes (> 5).
    byte[] tooManyCont =
        new byte[] {
          (byte) 0xff, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x01
        };
    assertThrows(IOException.class, () -> HpackCodec.readVarInt(new ByteCursor(tooManyCont), 7));

    // Oversized string length (> MAX_STRING_LENGTH).
    ByteArrayOutputStream hugeLen = new ByteArrayOutputStream();
    HpackCodec.writeVarInt(hugeLen, HpackCodec.MAX_STRING_LENGTH + 1, 7, 0x00);
    assertThrows(
        IOException.class, () -> HpackCodec.readString(new ByteCursor(hugeLen.toByteArray())));

    // Exact maximum header count (MAX_HEADER_FIELDS = 128) succeeds, while 129 fails.
    byte[] exactMaxHeaders = new byte[HpackCodec.MAX_HEADER_FIELDS];
    Arrays.fill(exactMaxHeaders, (byte) 0x88);
    try {
      assertThat(decoder.decodeHeaderBlock(exactMaxHeaders)).hasSize(HpackCodec.MAX_HEADER_FIELDS);
    } catch (IOException e) {
      throw new AssertionError("Decoding exact MAX_HEADER_FIELDS failed", e);
    }
    byte[] tooManyHeaders = new byte[HpackCodec.MAX_HEADER_FIELDS + 1];
    Arrays.fill(tooManyHeaders, (byte) 0x88);
    assertThrows(IOException.class, () -> decoder.decodeHeaderBlock(tooManyHeaders));
  }

  private static void writeIncrementalLiteral(
      ByteArrayOutputStream out, String name, String value) {
    out.write(0x40);
    byte[] n = name.getBytes(ISO_8859_1);
    HpackCodec.writeVarInt(out, n.length, 7, 0x00);
    out.writeBytes(n);
    byte[] v = value.getBytes(ISO_8859_1);
    HpackCodec.writeVarInt(out, v.length, 7, 0x00);
    out.writeBytes(v);
  }
}
