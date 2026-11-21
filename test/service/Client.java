// SPDX-License-Identifier: AGPL-3.0-only
//
// Java client of test/service/transparent-test.sh: one Anthropic request with
// the JDK's own HTTP client and default truststore, no proxy and no scrim
// configuration. Exits 0 on a 2xx answer.
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Client {
    public static void main(String[] args) throws Exception {
        String body = "{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"java " + args[1] + "\"}]}";
        HttpRequest req = HttpRequest.newBuilder(URI.create(args[0]))
            .header("content-type", "application/json")
            .header("x-api-key", "test")
            .header("anthropic-version", "2023-06-01")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
        System.out.println("java client: HTTP " + resp.statusCode());
        System.exit(resp.statusCode() / 100 == 2 ? 0 : 1);
    }
}
