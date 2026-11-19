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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HeaderField;
import com.google.tsunami.plugins.detectors.rce.cve2026123007.HpackDecoder.HpackException;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HpackDecoderTest {

  @Test
  public void decode_staticDynamicHuffmanAndSizeUpdates_decodesFieldsAndEvictsFifo()
      throws Exception {
    HpackDecoder decoder = new HpackDecoder();

    // Block 1: dynamic table size update (128 bytes), indexed :status=200 (0x88),
    // incremental indexed literal server="nginx" (0x40 + "server" + "nginx"),
    // Huffman literal without indexing x-test="www.example.com" (RFC 7541 C.4.1 Huffman bytes).
    byte[] huffmanWwwExampleCom = {
      (byte) 0xf1,
      (byte) 0xe3,
      (byte) 0xc2,
      (byte) 0xe5,
      (byte) 0xf2,
      0x3a,
      0x6b,
      (byte) 0xa0,
      (byte) 0xab,
      (byte) 0x90,
      (byte) 0xf4,
      (byte) 0xff
    };
    ByteArrayOutputStream block1 = new ByteArrayOutputStream();
    block1.write(0x3f); // 001_11111 + (128 - 31 = 97 = 0x61)
    block1.write(0x61);
    block1.write(0x88); // :status: 200
    block1.write(0x40); // literal with incremental indexing, new name
    writeRawString(block1, "server");
    writeRawString(block1, "nginx");
    block1.write(0x00); // literal without indexing, new name
    writeRawString(block1, "x-huff");
    block1.write(0x80 | huffmanWwwExampleCom.length);
    block1.writeBytes(huffmanWwwExampleCom);
    block1.write(0x10); // never indexed literal, new name
    writeRawString(block1, "x-never");
    writeRawString(block1, "secret");

    ImmutableList<HeaderField> fields1 = decoder.decode(block1.toByteArray());
    assertThat(fields1)
        .containsExactly(
            new HeaderField(":status", "200"),
            new HeaderField("server", "nginx"),
            new HeaderField("x-huff", "www.example.com"),
            new HeaderField("x-never", "secret"))
        .inOrder();

    // Block 2: reference dynamic entry 62 (0xbe -> server: nginx), then insert oversized entry
    // (> 128 bytes) to evict table cleanly, then shrink dynamic table to 0 (0x20).
    ByteArrayOutputStream block2 = new ByteArrayOutputStream();
    block2.write(0xbe); // dynamic index 62 -> server: nginx
    block2.write(0x7f); // incremental indexing with static index 62+ -> 0x40 | 0x3f, +0 = index 63?
    // Use incremental indexing with static name index 54 (server = 0x40 | 54 = 0x76).
    ByteArrayOutputStream block2Clean = new ByteArrayOutputStream();
    block2Clean.write(0xbe);
    block2Clean.write(0x76);
    writeRawString(block2Clean, "x".repeat(120)); // entry size = 6 + 120 + 32 = 158 > 128
    ImmutableList<HeaderField> fields2 = decoder.decode(block2Clean.toByteArray());
    assertThat(fields2)
        .containsExactly(
            new HeaderField("server", "nginx"), new HeaderField("server", "x".repeat(120)))
        .inOrder();

    // Block 3: dynamic size update to 0 followed by static :status 404 (0x8d).
    ImmutableList<HeaderField> fields3 = decoder.decode(new byte[] {0x20, (byte) 0x8d});
    assertThat(fields3).containsExactly(new HeaderField(":status", "404"));
  }

  @Test
  public void decode_dynamicTableFifoEvictionWithMultipleEntries_retainsNewestEntry()
      throws Exception {
    HpackDecoder decoder = new HpackDecoder();
    // Set dynamic table max size = 96 bytes (0x3f, 0x41), insert two 40-byte entries (each 8 + 32
    // = 40 bytes -> 80 <= 96), then insert a third 40-byte entry to evict the oldest FIFO entry.
    ByteArrayOutputStream block = new ByteArrayOutputStream();
    block.write(0x3f);
    block.write(0x41);
    for (String val : ImmutableList.of("v111", "v222", "v333")) {
      block.write(0x40);
      writeRawString(block, "k123");
      writeRawString(block, val);
    }
    block.write(0xbe); // newest entry ("v333")
    block.write(0xbf); // second-newest entry ("v222")

    ImmutableList<HeaderField> decoded = decoder.decode(block.toByteArray());
    assertThat(decoded)
        .containsExactly(
            new HeaderField("k123", "v111"),
            new HeaderField("k123", "v222"),
            new HeaderField("k123", "v333"),
            new HeaderField("k123", "v333"),
            new HeaderField("k123", "v222"))
        .inOrder();
  }

  @Test
  public void decode_zeroHeaderIndex_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class, () -> new HpackDecoder().decode(new byte[] {(byte) 0x80}));
    assertThat(thrown).hasMessageThat().contains("index");
  }

  @Test
  public void decode_outOfBoundsTableIndex_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class, () -> new HpackDecoder().decode(new byte[] {(byte) 0xff, 0x05}));
    assertThat(thrown).hasMessageThat().contains("index");
  }

  @Test
  public void decode_dynamicTableSizeExceedingProtocolCap_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class,
            () -> new HpackDecoder().decode(new byte[] {0x3f, (byte) 0xe2, 0x1f}));
    assertThat(thrown).hasMessageThat().contains("size update");
  }

  @Test
  public void decode_dynamicTableSizeUpdateAfterHeaderEmission_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class, () -> new HpackDecoder().decode(new byte[] {(byte) 0x88, 0x20}));
    assertThat(thrown).hasMessageThat().contains("size update");
  }

  @Test
  public void decode_truncatedIntegerContinuation_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class,
            () -> new HpackDecoder().decode(new byte[] {(byte) 0xff, (byte) 0x80}));
    assertThat(thrown).hasMessageThat().contains("integer");
  }

  @Test
  public void decode_integerShiftOverflow_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class,
            () ->
                new HpackDecoder()
                    .decode(
                        new byte[] {
                          (byte) 0xff,
                          (byte) 0x80,
                          (byte) 0x80,
                          (byte) 0x80,
                          (byte) 0x80,
                          (byte) 0x80,
                          0x01
                        }));
    assertThat(thrown).hasMessageThat().contains("integer");
  }

  @Test
  public void decode_integerExceedingMaxValue_throwsHpackException() {
    HpackException thrown =
        assertThrows(
            HpackException.class,
            () ->
                new HpackDecoder()
                    .decode(new byte[] {(byte) 0xff, (byte) 0x80, (byte) 0x80, 0x40}));
    assertThat(thrown).hasMessageThat().contains("integer");
  }

  @Test
  public void decode_truncatedStringHeaderOrBody_throwsHpackException() {
    HpackException eofHeader =
        assertThrows(HpackException.class, () -> new HpackDecoder().decode(new byte[] {0x00}));
    assertThat(eofHeader).hasMessageThat().contains("string");

    HpackException truncatedBody =
        assertThrows(
            HpackException.class,
            () -> new HpackDecoder().decode(new byte[] {0x01, 0x05, 'a', 'b'}));
    assertThat(truncatedBody).hasMessageThat().contains("string");
  }

  @Test
  public void decode_stringLengthExceedingMaxBytes_throwsHpackException() {
    HpackException rawOverflow =
        assertThrows(
            HpackException.class,
            () -> new HpackDecoder().decode(new byte[] {0x01, 0x7f, (byte) 0x82, 0x3f}));
    assertThat(rawOverflow).hasMessageThat().contains("string");

    ByteArrayOutputStream huffOverflow = new ByteArrayOutputStream();
    huffOverflow.write(0x01);
    huffOverflow.write(0xff);
    huffOverflow.write((4998 & 0x7f) | 0x80);
    huffOverflow.write(4998 >>> 7);
    huffOverflow.writeBytes(new byte[5125]);
    HpackException decodedOverflow =
        assertThrows(
            HpackException.class, () -> new HpackDecoder().decode(huffOverflow.toByteArray()));
    assertThat(decodedOverflow).hasMessageThat().contains("Huffman");
  }

  @Test
  public void decode_invalidHuffmanPaddingOrExplicitEos_throwsHpackException() {
    HpackException zeroPadding =
        assertThrows(
            HpackException.class,
            () -> new HpackDecoder().decode(new byte[] {0x01, (byte) 0x81, 0x00}));
    assertThat(zeroPadding).hasMessageThat().contains("padding");

    HpackException longPadding =
        assertThrows(
            HpackException.class,
            () ->
                new HpackDecoder()
                    .decode(new byte[] {0x01, (byte) 0x82, (byte) 0xff, (byte) 0xff}));
    assertThat(longPadding).hasMessageThat().contains("padding");

    HpackException eosSymbol =
        assertThrows(
            HpackException.class,
            () ->
                new HpackDecoder()
                    .decode(
                        new byte[] {
                          0x01, (byte) 0x84, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
                        }));
    assertThat(eosSymbol).hasMessageThat().contains("EOS");
  }

  private static void writeRawString(ByteArrayOutputStream out, String s) {
    byte[] bytes = s.getBytes(ISO_8859_1);
    out.write(bytes.length);
    out.writeBytes(bytes);
  }
}
