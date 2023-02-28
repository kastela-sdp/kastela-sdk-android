package com.hash.app;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.github.zafarkhaja.semver.Version;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.iwebpp.crypto.TweetNaclFast;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Request.Builder;

public class Client {
  private String expectedKastelaVersion = "0.2";

  private OkHttpClient httpClient;
  private String kastelaUrl;

  private static Gson gson = new Gson();

  public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

  public Client(String kastelaUrl) {

    this.kastelaUrl = kastelaUrl;

    // httpClient = HttpClient.newBuilder().build();
    httpClient = new OkHttpClient();
  }

  private Map<String, Object> request(String method, String url, Object body, Boolean CheckHeaders)
      throws Exception {
    // HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(url);
    Builder requestBuilder = new Request.Builder().url(url);

    // BodyPublisher requestBody = BodyPublishers.noBody();

    RequestBody reqBody = RequestBody.create("", JSON);
    if (body != null) {
      reqBody = RequestBody.create(gson.toJson(body), JSON);
      // requestBody = BodyPublishers.ofByteArray((byte[]) body);
      // requestBuilder.header("Content-Type", "application/json");
    }

    switch (method) {
      case "get":
        requestBuilder.get();
        break;
      case "post":
        requestBuilder.post(reqBody);
        break;
      case "put":
        requestBuilder.put(reqBody);
        break;
      case "delete":
        requestBuilder.delete();
        break;
      default:
        throw new Exception("Method Not Supported");
    }
    Request request = requestBuilder.build();
    Response response = httpClient.newCall(request).execute();
    if (CheckHeaders) {
      Map<String, List<String>> headers = response.headers().toMultimap();
      String actualVersion = headers.get("x-kastela-version").get(0).substring(1);
      Version v = Version.valueOf(actualVersion);
      if (!v.satisfies(expectedKastelaVersion.concat("| 0.0.0"))) {
        throw new Exception("kastela server version mismatch, expeced: v".concat(expectedKastelaVersion)
            .concat(".x, actual: v").concat(actualVersion));
      }
    }
    if (response.code() != 200) {
      throw new Exception(response.body().toString());
    }
    String resBody = response.body().string();
    Map<String, Object> result = gson.fromJson(resBody, new TypeToken<Map<String, Object>>() {
    }.getType());
    return result;
  }

  public Map<String, Object> secureProtectionSend(String credential, Object[][] data) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = null;

    com.iwebpp.crypto.TweetNaclFast.Box.KeyPair keyPair = TweetNaclFast.Box.keyPair();
    Map<String, Object> body = new HashMap<>();
    body.put("credential", credential);
    body.put("client_public_key", Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
    Map<String, Object> result = request("post", kastelaUrl.concat("/api/secure/protection/begin"), body,
        false);

    int x = 0;
    int y = 0;
    String[][] fullTexts = new String[data.length][];
    for (Object[] values : data) {
      if(fullTexts[x] == null) {
        fullTexts[x] = new String[values.length];
      }
      for (Object value : values) {
        out = new ObjectOutputStream(bos);
        out.writeObject(value);
        out.flush();
        byte[] dataByte = bos.toByteArray();

        byte[] nonce = TweetNaclFast.randombytes(TweetNaclFast.Box.nonceLength);
        byte[] serverPublicKey = Base64.getDecoder().decode(result.get("server_public_key").toString().getBytes());
        TweetNaclFast.Box box = new TweetNaclFast.Box(serverPublicKey, keyPair.getSecretKey());

        byte[] cipherText = box.box(dataByte, nonce);
        byte[] fullTextByteArray = new byte[nonce.length + cipherText.length];
        ByteBuffer buff = ByteBuffer.wrap(fullTextByteArray);
        buff.put(nonce);
        buff.put(cipherText);
        byte[] fullText = buff.array();
        fullTexts[x][y] = new String(Base64.getEncoder().encode(fullText));
        y++;
      }
      x++;
    }

    Map<String, Object> insertBody = new HashMap<>();
    insertBody.put("credential", credential);
    insertBody.put("data", fullTexts);
    
    bos.close();
    
    request("post", kastelaUrl.concat("/api/secure/protection/insert"),
        insertBody, true);
    return result;
  }

}
