package com.nhn.api.gateway.hmac;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CreateHmacAuth {

    private static final String DELIMITER = "\n";
    private final static String ALGORITHM = "HmacSHA256"; // HmacSHA256, HmacSHA1

    // -------------------------
    // API 콘솔 설정
    // -------------------------
    final String SECRET_KEY = "test"; // 비밀키
    

    @Test
    public void createSignature() throws InvalidKeyException, NoSuchAlgorithmException, URISyntaxException {

        // -------------------------
        // API 요청 정보
        // -------------------------
        HttpRequest httpRequest = HttpRequest.newBuilder()
                                             .GET()
                                             .uri(new URI("http://kr1-fcxv3lsbk1.dev-apigw.cloud.toast.com/api/method"))
                                             .headers("x-nhn-client-id", "nhn")
                                             .headers("x-nhn-client-ip", "10.0.0.1,10.0.0.2")
                                             .build();

        // 시간 조정
        int adjustClockSkew = -300;

        printCredential(httpRequest, adjustClockSkew);

    }


    private void printCredential(HttpRequest httpRequest, int adjustClockSkew) throws NoSuchAlgorithmException, InvalidKeyException {
        String requestDate = DateTime.now()
                                     .plusSeconds(adjustClockSkew)
                                     .toString(ISODateTimeFormat.dateTimeNoMillis());

        String credential;

        if (httpRequest.headers() != null) {
            Map<String, List<String>> headerMap = httpRequest.headers().map();
            credential = String.format("hmac algorithm=\"%s\", headers=\"%s\" , signature=\"%s\"", ALGORITHM, StringUtils.join(headerMap.keySet(), ","), getMessageDigest(requestDate, httpRequest));
        } else {
            credential = String.format("hmac algorithm=\"%s\", signature=\"%s\"", ALGORITHM, getMessageDigest(requestDate, httpRequest));
        }

        System.out.println();
        System.out.println("====================================");
        System.out.println("Credential");
        System.out.println("====================================");
        System.out.println("Authorization:" + credential);
        System.out.println("x-nhn-date:" + requestDate);
    }


    private String getMessageDigest(String requestDate, HttpRequest request) throws NoSuchAlgorithmException, InvalidKeyException {

        StringBuffer messages = new StringBuffer();

        messages.append(request.method().toUpperCase())
                .append(DELIMITER)
                .append(request.uri().getPath());

        if (request.uri().getQuery() != null) {
            messages.append("?");
            messages.append(request.uri().getQuery());
        }

        messages.append(DELIMITER)
                .append(requestDate);

        if (request.headers() != null) {
            messages.append(DELIMITER);
            Set<Map.Entry<String, List<String>>> headerMap = request.headers().map().entrySet();

            for (Map.Entry<String, List<String>> header : headerMap) {
                messages.append(StringUtils.lowerCase(header.getKey()));
                messages.append(":");
                messages.append(StringUtils.join(header.getValue(), ","));
                messages.append(DELIMITER);
            }

            messages.deleteCharAt(messages.length() - 1);
        }

        SecretKeySpec signingKey = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);

        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(signingKey);

        byte[] rawHmac = mac.doFinal(messages.toString().getBytes());

        System.out.println();
        System.out.println("====================================");
        System.out.println("SignToString");
        System.out.println("====================================");
        System.out.println(messages.toString());

        return Base64.encodeBase64String(rawHmac);
    }

}
