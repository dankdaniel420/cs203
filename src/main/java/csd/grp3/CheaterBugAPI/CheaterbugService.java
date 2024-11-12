package csd.grp3.CheaterBugAPI;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
public class CheaterbugService {

    private final RestTemplate restTemplate;
    private final String cheaterbugUrl;

    public CheaterbugService(RestTemplate restTemplate, 
    @Value("${cheaterbug.url}") String cheaterbugUrl) {
        this.restTemplate = restTemplate;
        this.cheaterbugUrl = cheaterbugUrl;
    }

    public CheaterbugResponse analyze(List<CheaterbugEntity> results) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Wrap the list in an HttpEntity and send it to the API
        HttpEntity<List<CheaterbugEntity>> entity = new HttpEntity<>(results, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                cheaterbugUrl,
                HttpMethod.POST,
                entity,
                Map.class
        );

        // Parse the API response into CheaterbugResponse
        Map<String, String> cheatProbability = (Map<String, String>) response.getBody().get("cheatProbability");
        Map<String, String> expectedProbability = (Map<String, String>) response.getBody().get("expectedProbability");

        return new CheaterbugResponse(cheatProbability, expectedProbability);
    }

    public boolean isSuspicious(CheaterbugResponse response) {
        if (response == null) {
            return false; // No response to analyze, so not suspicious
        }
    
        Map<String, String> cheatProbability = response.getCheatProbability();
        Map<String, String> expectedProbability = response.getExpectedProbability();
    
        // Parse "actual" and "99thPercentile" values from cheatProbability if they are numeric
        double cheatActual = parseProbabilityOrDefault(cheatProbability.get("actual"));
        double cheat99thPercentile = parseProbabilityOrDefault(cheatProbability.get("99thPercentile"));

        // Parse "actual" and "5thPercentile" values from expectedProbability if they are numeric
        double expectedActual = parseProbabilityOrDefault(expectedProbability.get("actual"));
        double expected5thPercentile = parseProbabilityOrDefault(expectedProbability.get("5thPercentile"));

        // If either percentile is missing or marked as "Not enough data", return false
        if (cheat99thPercentile == -1.0 || expected5thPercentile == -1.0) {
            return false;
        }

        // Define the conditions for suspicion
        boolean isCheatAbove99th = cheatActual > cheat99thPercentile;
        boolean isExpectedBelow5th = expectedActual < expected5thPercentile;

        // Return true if both conditions are met
        return isCheatAbove99th && isExpectedBelow5th;
    }
    
    // Helper method to parse probabilities, returning -1.0 if "Not enough data" is encountered
    private double parseProbabilityOrDefault(String value) {
        if (value == null || value.equals("Not enough data to calculate percentile probability")) {
            return -1.0; // Use -1.0 to indicate no valid data
        }
        return Double.parseDouble(value);
    }
}