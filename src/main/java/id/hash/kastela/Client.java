package id.hash.kastela;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

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
  private OkHttpClient httpClient;
  private String kastelaUrl;

  private static Gson gson = new Gson();

  public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

  public Client(String kastelaUrl) {

    this.kastelaUrl = kastelaUrl;

    httpClient = new OkHttpClient();
  }

  private Map<String, Object> request(String method, String url, Object body, Boolean CheckHeaders)
      throws Exception {
    Builder requestBuilder = new Request.Builder().url(url);

    RequestBody reqBody = RequestBody.create("", JSON);
    if (body != null) {
      reqBody = RequestBody.create(gson.toJson(body), JSON);
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
    if (response.code() != 200) {
      throw new Exception(response.body().toString());
    }
    String resBody = response.body().string();
    Map<String, Object> result = gson.fromJson(resBody, new TypeToken<Map<String, Object>>() {
    }.getType());
    return result;
  }

  /**
   * @param credential
   * @param values
   * @return
   * @throws Exception
   */
  public Map<String, Object> secureProtectionSend(String credential, Object[][] values) throws Exception {
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
    String[][] fullTexts = new String[values.length][];
    for (Object[] value : values) {
      if (fullTexts[x] == null) {
        fullTexts[x] = new String[value.length];
      }
      for (Object v : value) {
        out = new ObjectOutputStream(bos);
        out.writeObject(gson.toJson(v));
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
    insertBody.put("values", fullTexts);

    bos.close();

    Map<String, Object> storeResult = request("post",
        kastelaUrl.concat("/api/secure/protection/store"),
        insertBody, true);

    Map<String, Object> data = new HashMap<>();
    data.put("tokens", storeResult.get("tokens"));
    return data;
  }

  /**
   * @param credential
   * @param values
   * @return
   * @throws Exception
   */
  public Map<String, Object> secureVaultSend(String credential, Object[][] values) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = null;

    com.iwebpp.crypto.TweetNaclFast.Box.KeyPair keyPair = TweetNaclFast.Box.keyPair();
    Map<String, Object> body = new HashMap<>();
    body.put("credential", credential);
    body.put("client_public_key", Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
    Map<String, Object> result = request("post", kastelaUrl.concat("/api/secure/vault/begin"), body,
        false);

    int x = 0;
    int y = 0;
    String[][] fullTexts = new String[values.length][];
    for (Object[] value : values) {
      if (fullTexts[x] == null) {
        fullTexts[x] = new String[value.length];
      }
      for (Object v : value) {
        out = new ObjectOutputStream(bos);
        out.writeObject(gson.toJson(v));
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
    insertBody.put("values", fullTexts);

    bos.close();

    Map<String, Object> storeResult = request("post",
        kastelaUrl.concat("/api/secure/vault/store"),
        insertBody, true);
    Map<String, Object> data = new HashMap<>();
    data.put("tokens", storeResult.get("tokens"));
    return data;
  }

  /**
   * @param credential
   * @param tokens
   * @return
   * @throws Exception
   */
  public Map<String, Object> secureProtectionReceive(String credential, String[][] tokens) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    com.iwebpp.crypto.TweetNaclFast.Box.KeyPair keyPair = TweetNaclFast.Box.keyPair();
    Map<String, Object> body = new HashMap<>();
    body.put("credential", credential);
    body.put("client_public_key", Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
    Map<String, Object> result = request("post", kastelaUrl.concat("/api/secure/protection/begin"), body,
        false);

    Map<String, Object> fetchBody = new HashMap<>();
    fetchBody.put("credential", credential);
    fetchBody.put("tokens", tokens);
    Map<String, Object> fetchResult = request("post", kastelaUrl.concat("/api/secure/protection/fetch"), fetchBody,
        false);

    ArrayList<?> fullTexts = fetchResult.get("values") instanceof ArrayList<?>
        ? (ArrayList<?>) fetchResult.get("values")
        : null;

    int x = 0;
    int y = 0;
    Object[][] values = new Object[fullTexts.size()][];
    for (Object valueRaw : fullTexts) {
      ArrayList<?> value = valueRaw instanceof ArrayList<?> ? (ArrayList<?>) valueRaw : null;
      if (values[x] == null) {
        values[x] = new Object[value.size()];
      }
      for (Object vRaw : value) {
        String v = vRaw instanceof String ? (String) vRaw : null;
        byte[] fulltext = Base64.getDecoder().decode(v);

        ByteBuffer bb = ByteBuffer.wrap(fulltext);

        byte[] nonce = new byte[TweetNaclFast.Box.nonceLength];
        byte[] cipherText = new byte[fulltext.length - TweetNaclFast.Box.nonceLength];
        bb.get(nonce, 0, TweetNaclFast.Box.nonceLength);
        bb.get(cipherText, 0, fulltext.length - TweetNaclFast.Box.nonceLength);

        byte[] serverPublicKey = Base64.getDecoder().decode(result.get("server_public_key").toString().getBytes());
        TweetNaclFast.Box box = new TweetNaclFast.Box(serverPublicKey, keyPair.getSecretKey());

        byte[] plaintext = box.open(cipherText, nonce);
        String rawtext = new String(plaintext, StandardCharsets.UTF_8);
        values[x][y] = gson.fromJson(rawtext, new TypeToken<Object>() {
        }.getType());
        y++;
      }
      x++;
    }
    Map<String, Object> data = new HashMap<>();
    data.put("values", values);

    bos.close();
    return data;
  }

  /**
   * @param credential
   * @param tokens
   * @return
   * @throws Exception
   */
  public Map<String, Object> secureVaultReceive(String credential, String[][] tokens) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    com.iwebpp.crypto.TweetNaclFast.Box.KeyPair keyPair = TweetNaclFast.Box.keyPair();
    Map<String, Object> body = new HashMap<>();
    body.put("credential", credential);
    body.put("client_public_key", Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
    Map<String, Object> result = request("post", kastelaUrl.concat("/api/secure/vault/begin"), body,
        false);

    Map<String, Object> fetchBody = new HashMap<>();
    fetchBody.put("credential", credential);
    fetchBody.put("tokens", tokens);
    Map<String, Object> fetchResult = request("post", kastelaUrl.concat("/api/secure/vault/fetch"), fetchBody,
        false);

    ArrayList<?> fullTexts = fetchResult.get("values") instanceof ArrayList<?>
        ? (ArrayList<?>) fetchResult.get("values")
        : null;

    int x = 0;
    int y = 0;
    Object[][] values = new Object[fullTexts.size()][];
    for (Object valueRaw : fullTexts) {
      ArrayList<?> value = valueRaw instanceof ArrayList<?> ? (ArrayList<?>) valueRaw : null;
      if (values[x] == null) {
        values[x] = new Object[value.size()];
      }
      for (Object vRaw : value) {
        String v = vRaw instanceof String ? (String) vRaw : null;
        byte[] fulltext = Base64.getDecoder().decode(v);

        ByteBuffer bb = ByteBuffer.wrap(fulltext);

        byte[] nonce = new byte[TweetNaclFast.Box.nonceLength];
        byte[] cipherText = new byte[fulltext.length - TweetNaclFast.Box.nonceLength];
        bb.get(nonce, 0, TweetNaclFast.Box.nonceLength);
        bb.get(cipherText, 0, fulltext.length - TweetNaclFast.Box.nonceLength);

        byte[] serverPublicKey = Base64.getDecoder().decode(result.get("server_public_key").toString().getBytes());
        TweetNaclFast.Box box = new TweetNaclFast.Box(serverPublicKey, keyPair.getSecretKey());

        byte[] plaintext = box.open(cipherText, nonce);
        String rawtext = new String(plaintext, StandardCharsets.UTF_8);
        values[x][y] = gson.fromJson(rawtext, new TypeToken<Object>() {
        }.getType());
        y++;
      }
      x++;
    }
    Map<String, Object> data = new HashMap<>();
    data.put("values", values);

    bos.close();
    return data;
  }
}