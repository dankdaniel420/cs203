package csd.grp3.CheaterBugAPITest;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import csd.grp3.CheaterBugAPI.*;
import csd.grp3.user.User;

@SpringBootTest
public class CheaterbugServiceIntegrationTest {

    @Autowired
    private CheaterbugService cheaterbugService;

    @Test
    public void testAnalyzeWithRealApiCall() {
        // Prepare the input data (a list of CheaterbugEntity objects)
        CheaterbugEntity entity1 = new CheaterbugEntity(0.5, 0.9);
        CheaterbugEntity entity2 = new CheaterbugEntity(1.0, 0.8);
        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2);

        // Call the service method
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);

        // Print the response to see actual values
        System.out.println("Cheat Probability: " + response.getCheatProbability());
        System.out.println("Expected Probability: " + response.getExpectedProbability());

        // Assertions to verify the response
        assertNotNull(response, "The response should not be null");
        assertNotNull(response.getCheatProbability(), "Cheat probability should not be null");
        assertNotNull(response.getExpectedProbability(), "Expected probability should not be null");

        // Check specific values if known or expected structure
        assertTrue(response.getCheatProbability().containsKey("99thPercentile"), "Expected key '99thPercentile' not found.");
        assertTrue(response.getExpectedProbability().containsKey("5thPercentile"), "Expected key '5thPercentile' not found.");
    }

    @Test
    public void testAnalyze_NormalPlay_NoSuspicion() {
        // Prepare normal play data
        CheaterbugEntity entity1 = new CheaterbugEntity(0.5, 0.6);
        CheaterbugEntity entity2 = new CheaterbugEntity(1.0, 0.8);
        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2);

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response);
        assertFalse(cheaterbugService.isSuspicious(response), "Expected no suspicious activity in normal play.");
    }

    @Test
    public void testAnalyze_ExpectedBelow5th_CheatAbove99th_Suspicion_WithMoreData() {
        // Adding more data points to simulate a richer dataset for suspicion detection
        CheaterbugEntity entity1 = new CheaterbugEntity(1.0, 0.2);
        CheaterbugEntity entity2 = new CheaterbugEntity(1.0, 0.2);
        CheaterbugEntity entity3 = new CheaterbugEntity(1.0, 0.2);
        CheaterbugEntity entity4 = new CheaterbugEntity(1.0, 0.2);
        CheaterbugEntity entity5 = new CheaterbugEntity(1.0, 0.2);

        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2, entity3, entity4, entity5);

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response, "The response should not be null.");
        assertTrue(cheaterbugService.isSuspicious(response), 
            "Expected suspicious activity with low expected scores and consistently high actual scores.");
    }

    @Test
    public void testAnalyze_HighExpectedScore_NoSuspicion() {
        // High expected score (player likely to win); should not be flagged as suspicious
        CheaterbugEntity entity1 = new CheaterbugEntity(1.0, 0.9);
        CheaterbugEntity entity2 = new CheaterbugEntity(1.0, 0.9);
        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2);

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response);
        assertFalse(cheaterbugService.isSuspicious(response), "Expected no suspicious activity with high expected scores.");
    }

    @Test
    public void testAnalyze_CheatingPatternWithMixedScores() {
        // Mixed scores with one expected to trigger suspicion
        CheaterbugEntity entity1 = new CheaterbugEntity(1.0, 0.3);
        CheaterbugEntity entity2 = new CheaterbugEntity(1.0, 0.2); // High actual, low expected -> suspicious
        CheaterbugEntity entity3 = new CheaterbugEntity(0.5, 0.1);
        CheaterbugEntity entity4 = new CheaterbugEntity(1.0, 0.1);

        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2, entity3, entity4);

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response);
        assertTrue(cheaterbugService.isSuspicious(response), "Expected suspicious activity with a high actual score in a low-expected match.");
    }

    @Test
    public void testAnalyze_LowActualScores_NoSuspicion() {
        // All scores are low, no strong indication of cheating
        CheaterbugEntity entity1 = new CheaterbugEntity(0.0, 0.5);
        CheaterbugEntity entity2 = new CheaterbugEntity(0.0, 0.6);
        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2);

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response);
        assertFalse(cheaterbugService.isSuspicious(response), "Expected no suspicion with uniformly low actual scores.");
    }

    @Test
    public void testAnalyze_WithEloScores_isSus() {
        // Prepare the input data (a list of users objects with elo)
        User user = new User("player1", "password1", "ROLE_PLAYER", 100);
        User opp1 = new User("player3", "password3", "ROLE_PLAYER", 120);
        // User opp2 = new User("player5", "password5", "ROLE_PLAYER", 130);
        // User opp3 = new User("player2", "password2", "ROLE_PLAYER", 140);
        // User opp4 = new User("player4", "password4", "ROLE_PLAYER", 150);
        // User opp5 = new User("player6", "password6", "ROLE_PLAYER", 200);
        User opp6 = new User("player7", "password7", "ROLE_PLAYER", 220);
        // User opp7 = new User("player8", "password8", "ROLE_PLAYER", 240);
        User opp8 = new User("player9", "password9", "ROLE_PLAYER", 260);
        User opp9 = new User("player10", "password10", "ROLE_PLAYER", 280);
 
        List<CheaterbugEntity> requestPayload = List.of(
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp1.getELO() - user.getELO()) / 200.0))),
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp8.getELO() - user.getELO()) / 200.0))),
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp6.getELO() - user.getELO()) / 200.0))),
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp9.getELO() - user.getELO()) / 200.0))),
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp9.getELO() - user.getELO()) / 200.0))),
            new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp8.getELO() - user.getELO()) / 200.0)))
            // new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp7.getELO() - user.getELO()) / 200.0))),
            // new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp8.getELO() - user.getELO()) / 200.0))),
            // new CheaterbugEntity(1.0, 1.0 / (1 + Math.pow(10, (opp9.getELO() - user.getELO()) / 200.0)))
        );

        // Call the service method and check results
        CheaterbugResponse response = cheaterbugService.analyze(requestPayload);
        assertNotNull(response);
        assertTrue(cheaterbugService.isSuspicious(response));
    }
}
