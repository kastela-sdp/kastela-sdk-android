package id.hash.kastela;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.util.HashMap;
import java.util.Map;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class AppTest {
    private static Gson gson = new Gson();

    public static void main(String[] args) throws Exception {
        HttpClient httpClient = HttpClient.newBuilder().build();

        String[] ids = new String[] { "45597d20-2dc5-4246-af6e-7d0a62528f3c" };
        String[][] data = new String[][] { new String[] { "disyam@hash.id" } };

        Map<String, Object> rawBody = new HashMap<>();
        rawBody.put("operation", "WRITE");
        rawBody.put("protection_ids", ids);
        rawBody.put("ttl", 1);
        BodyPublisher body = BodyPublishers.ofString(gson.toJson(rawBody));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:4000/api/secure/protection/init"))
                .POST(body).header("Content-Type", "application/json").build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
        Map<String, Object> result = gson.fromJson(response.body(), new TypeToken<Map<String, Object>>() {
        }.getType());

        Client client = new Client("http://127.0.0.1:3200");
        Map<String, Object> sendResult = client.secureProtectionSend(result.get("credential").toString(), data);
        System.out.println(sendResult);
    }
}
