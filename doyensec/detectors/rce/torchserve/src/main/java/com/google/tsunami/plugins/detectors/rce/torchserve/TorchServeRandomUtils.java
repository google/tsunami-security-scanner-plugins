/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.torchserve;

import java.security.MessageDigest;
import java.util.UUID;

public class TorchServeRandomUtils {
    public String getRandomValue() {
        return UUID.randomUUID().toString();
    }

    /**
     * Compares the provided hash with the MD5 hash of the given value.
     *
     * @param hash        The hash to compare against the expected MD5 hash.
     * @param randomValue The value used for generating the expected MD5 hash.
     * @return True if the provided hash matches the MD5 hash of the given value,
     *         false otherwise.
     */
    public boolean validateHash(String hash, String randomValue) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(randomValue.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString().equals(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
