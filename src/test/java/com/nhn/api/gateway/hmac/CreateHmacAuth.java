package com.nhn.api.gateway.hmac;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections4.CollectionUtils;
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

public class CreateHmacAuth {

    private static final String DELIMITER = "\n";
    private final static String ALGORITHM = "HmacSHA256"; // HmacSHA256, HmacSHA1

    // -------------------------
    // API 콘솔 설정
    // -------------------------
    final String SECRET_KEY = "test"; // 비밀키
    final List<String> FORCE_REQUEST_HEADER_LIST = List.of("Host");        // 필수 검증 헤더 : key:value 형식으로 입력


    @Test
    public void createSignature() throws InvalidKeyException, NoSuchAlgorithmException, URISyntaxException {

        // -------------------------
        // API 요청 정보
        // -------------------------
        HttpRequest httpRequest = HttpRequest.newBuilder()
                                             .GET()
                                             .uri(new URI("http://kr1-rhcejfazui.dev-apigw.cloud.toast.com/set-response-header"))
                                             .headers("header1", "header1-value")
                                             .headers("header2", "header2-value")
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

        if (CollectionUtils.isNotEmpty(FORCE_REQUEST_HEADER_LIST) && request.headers() != null) {
            messages.append(DELIMITER);
            for (String header : FORCE_REQUEST_HEADER_LIST) {
                messages.append(StringUtils.lowerCase(header));
                messages.append(":");
                messages.append(StringUtils.join(request.headers().allValues(header), ","));
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
