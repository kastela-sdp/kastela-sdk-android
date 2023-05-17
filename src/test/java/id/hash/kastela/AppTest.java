package id.hash.kastela;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class AppTest {
    private static Gson gson = new Gson();
    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    public static void main(String[] args) throws Exception {
        Client client = new Client("http://127.0.0.1:3200");
        OkHttpClient httpClient = new OkHttpClient();

        String[] protectionIds = new String[] { "f3f9a010-95e3-478d-ad8b-329429af48c8" };
        String[] vaultIds = new String[] { "94544c8f-eb55-4bf6-b274-33c368428ddd" };
        String[][] protectionData = new String[][] { new String[] { "disyam@hash.id" } };
        String[][] protectionTokens = new String[][] { new String[] { "132e9021-1817-4a50-b9a4-36cca016d0ca" } };
        String[][] vaultData = new String[][] { new String[] {
                "{\n    \"employee\": [\n      {\n        \"id\": \"1\",\n        \"firstName\": \"Tom\",\n        \"lastName\": \"Cruise\",\n        \"photo\": \"https://jsonformatter.org/img/tom-cruise.jpg\"\n      },\n      {\n        \"id\": \"2\",\n        \"firstName\": \"Maria\",\n        \"lastName\": \"Sharapova\",\n        \"photo\": \"https://jsonformatter.org/img/Maria-Sharapova.jpg\"\n      },\n      {\n        \"id\": \"3\",\n        \"firstName\": \"Robert\",\n        \"lastName\": \"Downey Jr.\",\n        \"photo\": \"https://jsonformatter.org/img/Robert-Downey-Jr.jpg\"\n      }\n    ]\n}" } };
        String[][] vaultTokens = new String[][] { new String[] {
                "01H0M79NQFRYGTXX25NGEWR74Y",
                "01H0M79NQG93MY0HE8S91D053B"
        } };

        Map<String, Object> rawProtectionInitBodyWrite = new HashMap<>();
        rawProtectionInitBodyWrite.put("operation", "WRITE");
        rawProtectionInitBodyWrite.put("protection_ids", protectionIds);
        rawProtectionInitBodyWrite.put("ttl", 1);

        Request requestProtectionInitBodyWrite = new Request.Builder()
                .url("http://127.0.0.1:4000/api/secure/protection/init")
                .post(RequestBody.create(gson.toJson(rawProtectionInitBodyWrite), JSON)).build();

        Response responseProtectionInitWrite = httpClient.newCall(requestProtectionInitBodyWrite).execute();
        String resProtectionInitBodyWrite = responseProtectionInitWrite.body().string();
        Map<String, Object> resultProtectionInitBodyWrite = gson.fromJson(resProtectionInitBodyWrite,
                new TypeToken<Map<String, Object>>() {
                }.getType());

        Map<String, Object> sendResult = client
                .secureProtectionSend(resultProtectionInitBodyWrite.get("credential").toString(), protectionData);
        System.out.printf("secure protection send result : ");
        System.out.println(sendResult);

        Map<String, Object> rawProtectionInitBodyRead = new HashMap<>();
        rawProtectionInitBodyRead.put("operation", "READ");
        rawProtectionInitBodyRead.put("protection_ids", protectionIds);
        rawProtectionInitBodyRead.put("ttl", 1);

        Request requestProtectionInitBodyRead = new Request.Builder()
                .url("http://127.0.0.1:4000/api/secure/protection/init")
                .post(RequestBody.create(gson.toJson(rawProtectionInitBodyRead), JSON)).build();

        Response responseProtectionInitRead = httpClient.newCall(requestProtectionInitBodyRead).execute();
        String resProtectionInitBodyRead = responseProtectionInitRead.body().string();
        Map<String, Object> resultProtectionInitBodyRead = gson.fromJson(resProtectionInitBodyRead,
                new TypeToken<Map<String, Object>>() {
                }.getType());

        Map<String, Object> receiveResult = client
                .secureProtectionReceive(resultProtectionInitBodyRead.get("credential").toString(), protectionTokens);
        System.out.printf("secure protection receive result : ");
        System.out.println(Arrays.deepToString((Object[]) receiveResult.get("values")));

        Map<String, Object> rawVaultInitBodyWrite = new HashMap<>();
        rawVaultInitBodyWrite.put("operation", "WRITE");
        rawVaultInitBodyWrite.put("vault_ids", vaultIds);
        rawVaultInitBodyWrite.put("ttl", 1);

        Request requestVaultInitBodyWrite = new Request.Builder()
                .url("http://127.0.0.1:4000/api/secure/vault/init")
                .post(RequestBody.create(gson.toJson(rawVaultInitBodyWrite), JSON)).build();

        Response responseVaultInitWrite = httpClient.newCall(requestVaultInitBodyWrite).execute();
        String resVaultInitBodyWrite = responseVaultInitWrite.body().string();
        Map<String, Object> resultVaultInitBodyWrite = gson.fromJson(resVaultInitBodyWrite,
                new TypeToken<Map<String, Object>>() {
                }.getType());

        Map<String, Object> sendVaultResult = client
                .secureVaultSend(resultVaultInitBodyWrite.get("credential").toString(), vaultData);
        System.out.printf("secure vault send result : ");
        System.out.println(sendVaultResult);

        Map<String, Object> rawVaultInitBodyRead = new HashMap<>();
        rawVaultInitBodyRead.put("operation", "READ");
        rawVaultInitBodyRead.put("vault_ids", vaultIds);
        rawVaultInitBodyRead.put("ttl", 1);

        Request requestVaultInitBodyRead = new Request.Builder()
                .url("http://127.0.0.1:4000/api/secure/vault/init")
                .post(RequestBody.create(gson.toJson(rawVaultInitBodyRead), JSON)).build();

        Response responseVaultInitRead = httpClient.newCall(requestVaultInitBodyRead).execute();
        String resVaultInitBodyRead = responseVaultInitRead.body().string();
        Map<String, Object> resultVaultInitBodyRead = gson.fromJson(resVaultInitBodyRead,
                new TypeToken<Map<String, Object>>() {
                }.getType());

        Map<String, Object> receiveVaultResult = client
                .secureVaultReceive(resultVaultInitBodyRead.get("credential").toString(), vaultTokens);
        System.out.printf("secure protection receive result : ");
        System.out.println(Arrays.deepToString((Object[]) receiveVaultResult.get("values")));
    }
}
