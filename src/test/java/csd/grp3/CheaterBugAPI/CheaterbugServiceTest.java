package csd.grp3.CheaterBugAPI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class CheaterbugServiceTest {

    @InjectMocks
    private CheaterbugService cheaterbugService;

    @Test
    public void testIsSuspicious_WhenCheatAbove99thAndExpectedBelow5th_ShouldReturnTrue() {
        // Arrange: Mock response with values indicating suspicion
        Map<String, String> cheatProbability = Map.of("actual", "0.98", "99thPercentile", "0.95");
        Map<String, String> expectedProbability = Map.of("actual", "0.02", "5thPercentile", "0.04");
        CheaterbugResponse mockResponse = new CheaterbugResponse(cheatProbability, expectedProbability);

        // Act: Call isSuspicious
        boolean result = cheaterbugService.isSuspicious(mockResponse);

        // Assert: Should return true for suspicious case
        assertTrue(result, "Expected result to be true when cheat is above 99th percentile and expected below 5th percentile");
    }

    @Test
    public void testIsSuspicious_WhenCheatBelow99thOrExpectedAbove5th_ShouldReturnFalse() {
        // Arrange: Mock response with non-suspicious values
        Map<String, String> cheatProbability = Map.of("actual", "0.93", "99thPercentile", "0.95");
        Map<String, String> expectedProbability = Map.of("actual", "0.05", "5thPercentile", "0.04");
        CheaterbugResponse mockResponse = new CheaterbugResponse(cheatProbability, expectedProbability);

        // Act: Call isSuspicious
        boolean result = cheaterbugService.isSuspicious(mockResponse);

        // Assert: Should return false for non-suspicious case
        assertFalse(result, "Expected result to be false when cheat is below 99th percentile or expected is above 5th percentile");
    }

    @Test
    public void testIsSuspicious_WhenNotEnoughData_ShouldReturnFalse() {
        // Arrange: Mock response with "Not enough data" messages
        Map<String, String> cheatProbability = Map.of("actual", "0.98", "99thPercentile", "Not enough data to calculate percentile probability");
        Map<String, String> expectedProbability = Map.of("actual", "0.02", "5thPercentile", "Not enough data to calculate percentile probability");
        CheaterbugResponse mockResponse = new CheaterbugResponse(cheatProbability, expectedProbability);

        // Act: Call isSuspicious
        boolean result = cheaterbugService.isSuspicious(mockResponse);

        // Assert: Should return false if data is not sufficient
        assertFalse(result, "Expected result to be false when there's not enough data to calculate probabilities");
    }
    
    @Test
    public void testIsSuspicious_WhenResponseIsNull_ShouldReturnFalse() {
        // Act: Call isSuspicious with null response
        boolean result = cheaterbugService.isSuspicious(null);

        // Assert: Should return false for null response
        assertFalse(result, "Expected result to be false when response is null");
    }
}
