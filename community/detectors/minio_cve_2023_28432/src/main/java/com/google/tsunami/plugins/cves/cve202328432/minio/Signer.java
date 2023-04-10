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
package com.google.tsunami.plugins.cves.cve202328432.minio;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;
import com.google.common.io.BaseEncoding;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.tsunami.proto.HttpHeader;
import com.google.tsunami.proto.HttpHeaderOrBuilder;
import okhttp3.HttpUrl;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpHeaders;

import static com.google.tsunami.plugins.cves.cve202328432.minio.Time.AMZ_DATE_FORMAT;

public class Signer {
    //
    // Excerpts from @lsegal - https://github.com/aws/aws-sdk-js/issues/659#issuecomment-120477258
    //
    // * User-Agent
    // This is ignored from signing because signing this causes problems with generating pre-signed
    // URLs (that are executed by other agents) or when customers pass requests through proxies, which
    // may modify the user-agent.
    //
    // * Authorization
    // Is skipped for obvious reasons.
    //
    // * Accept-Encoding
    // Some S3 servers like Hitachi Content Platform do not honour this header for signature
    // calculation.
    //
    private static final Set<String> IGNORED_HEADERS =
            ImmutableSet.of("accept-encoding", "authorization", "user-agent");

    private HttpRequest request;
    private String contentSha256;
    private ZonedDateTime date;
    private String region;
    private String accessKey;
    private String secretKey;
    private String prevSignature;

    private String scope;
    private Map<String, String> canonicalHeaders;
    private String signedHeaders;
    private HttpUrl url;
    private String canonicalQueryString;
    private String canonicalRequest;
    private String canonicalRequestHash;
    private String stringToSign;
    private byte[] signingKey;
    private String signature;
    private String authorization;

    /**
     * Create new Signer object for V4.
     *
     * @param request HTTP Request object.
     * @param contentSha256 SHA-256 hash of request payload.
     * @param date Date to be used to sign the request.
     * @param region Amazon AWS region for the request.
     * @param accessKey Access Key string.
     * @param secretKey Secret Key string.
     * @param prevSignature Previous signature of chunk upload.
     */
    private Signer(
            HttpRequest request,
            String contentSha256,
            ZonedDateTime date,
            String region,
            String accessKey,
            String secretKey,
            String prevSignature) {
        this.request = request;
        this.contentSha256 = contentSha256;
        this.date = date;
        this.region = region;
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.prevSignature = prevSignature;
    }

    private void setScope(String serviceName) {
        this.scope =
                this.date.format(Time.SIGNER_DATE_FORMAT)
                        + "/"
                        + this.region
                        + "/"
                        + serviceName
                        + "/aws4_request";
    }

    private void setCanonicalHeaders(Set<String> ignored_headers) {
        this.canonicalHeaders = new TreeMap<>();

        HttpHeaders headers = this.request.headers();
        for (String name : headers.names()) {
            String signedHeader = name.toLowerCase(Locale.US);
            if (!ignored_headers.contains(signedHeader)) {
                // Convert and add header values as per
                // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
                // * Header having multiple values should be converted to comma separated values.
                // * Multi-spaced value of header should be trimmed to single spaced value.
                this.canonicalHeaders.put(
                        signedHeader,
                        headers.get(name).stream()
                                .map(
                                        value -> {
                                            return value.replaceAll("( +)", " ");
                                        })
                                .collect(Collectors.joining(",")));
            }
        }

        this.signedHeaders = Joiner.on(";").join(this.canonicalHeaders.keySet());
    }

    private void setCanonicalQueryString() {
        String encodedQuery = this.url.encodedQuery();
        if (encodedQuery == null) {
            this.canonicalQueryString = "";
            return;
        }

        // Building a multimap which only order keys, ordering values is not performed
        // until MinIO server supports it.
        Multimap<String, String> signedQueryParams =
                MultimapBuilder.treeKeys().arrayListValues().build();

        for (String queryParam : encodedQuery.split("&")) {
            String[] tokens = queryParam.split("=");
            if (tokens.length > 1) {
                signedQueryParams.put(tokens[0], tokens[1]);
            } else {
                signedQueryParams.put(tokens[0], "");
            }
        }

        this.canonicalQueryString =
                Joiner.on("&").withKeyValueSeparator("=").join(signedQueryParams.entries());
    }

    private void setCanonicalRequest() throws NoSuchAlgorithmException {
        setCanonicalHeaders(IGNORED_HEADERS);
        this.url = HttpUrl.get(this.request.url());
        setCanonicalQueryString();

        // CanonicalRequest =
        //   HTTPRequestMethod + '\n' +
        //   CanonicalURI + '\n' +
        //   CanonicalQueryString + '\n' +
        //   CanonicalHeaders + '\n' +
        //   SignedHeaders + '\n' +
        //   HexEncode(Hash(RequestPayload))
        this.canonicalRequest =
                this.request.method()
                        + "\n"
                        + this.url.encodedPath()
                        + "\n"
                        + this.canonicalQueryString
                        + "\n"
                        + Joiner.on("\n").withKeyValueSeparator(":").join(this.canonicalHeaders)
                        + "\n\n"
                        + this.signedHeaders
                        + "\n"
                        + this.contentSha256;

        this.canonicalRequestHash = Digest.sha256Hash(this.canonicalRequest);
    }

    private void setStringToSign() {
        this.stringToSign =
                "AWS4-HMAC-SHA256"
                        + "\n"
                        + this.date.format(AMZ_DATE_FORMAT)
                        + "\n"
                        + this.scope
                        + "\n"
                        + this.canonicalRequestHash;
    }


    private void setSigningKey(String serviceName)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String aws4SecretKey = "AWS4" + this.secretKey;

        byte[] dateKey =
                sumHmac(
                        aws4SecretKey.getBytes(StandardCharsets.UTF_8),
                        this.date.format(Time.SIGNER_DATE_FORMAT).getBytes(StandardCharsets.UTF_8));

        byte[] dateRegionKey = sumHmac(dateKey, this.region.getBytes(StandardCharsets.UTF_8));

        byte[] dateRegionServiceKey =
                sumHmac(dateRegionKey, serviceName.getBytes(StandardCharsets.UTF_8));

        this.signingKey =
                sumHmac(dateRegionServiceKey, "aws4_request".getBytes(StandardCharsets.UTF_8));
    }

    private void setSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] digest = sumHmac(this.signingKey, this.stringToSign.getBytes(StandardCharsets.UTF_8));
        this.signature = BaseEncoding.base16().encode(digest).toLowerCase(Locale.US);
    }

    private void setAuthorization() {
        this.authorization =
                "AWS4-HMAC-SHA256 Credential="
                        + this.accessKey
                        + "/"
                        + this.scope
                        + ", SignedHeaders="
                        + this.signedHeaders
                        + ", Signature="
                        + this.signature;
    }


    /** Returns signed request object for given request, region, access key and secret key. */
    public static HttpRequest signV4(
            String serviceName,
            HttpRequest request,
            String region,
            String accessKey,
            String secretKey,
            String contentSha256)
            throws NoSuchAlgorithmException, InvalidKeyException {

        ZonedDateTime date = ZonedDateTime.parse(request.headers().get("x-amz-date").get(), Time.AMZ_DATE_FORMAT);

        Signer signer = new Signer(request, contentSha256, date, region, accessKey, secretKey, null);
        signer.setScope(serviceName);
        signer.setCanonicalRequest();
        signer.setStringToSign();
        signer.setSigningKey(serviceName);
        signer.setSignature();
        signer.setAuthorization();

        // Build headers from original request
        HttpHeaders.Builder newHeaders = request.headers().builder();
        for (String name : request.headers().names()) {
            newHeaders.addHeader(name, request.headers().get(name).get());
        }

        // Add signed authorization header
        newHeaders.addHeader("Authorization", signer.authorization);

        // build the new / signed request
        HttpRequest.Builder newRequest = request.builder();
        newRequest.setUrl(request.url());
        newRequest.setMethod(request.method());

        newRequest.setHeaders(newHeaders.build());

        return newRequest.build();
    }

    /** Returns HMacSHA256 digest of given key and data. */
    public static byte[] sumHmac(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(data);

        return mac.doFinal();
    }
}

