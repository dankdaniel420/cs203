package csd.grp3.CheaterBugAPI;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

@ExtendWith(MockitoExtension.class)
public class CheaterbugControllerTest {

    @Mock
    private CheaterbugService cheaterbugService;

    @InjectMocks
    private CheaterbugController cheaterbugController;

    @Test
    public void testAnalyze() {
        // Prepare the input data (a list of CheaterbugEntity objects with actual and expected scores)
        CheaterbugEntity entity1 = new CheaterbugEntity(0.5, 0.9);
        CheaterbugEntity entity2 = new CheaterbugEntity(0.6, 0.8);
        List<CheaterbugEntity> requestPayload = List.of(entity1, entity2);

        // Prepare the mock response data with expected probabilities
        Map<String, String> cheatProbability = Map.of("99thPercentile", "0.95");
        Map<String, String> expectedProbability = Map.of("5thPercentile", "0.04");
        CheaterbugResponse mockResponse = new CheaterbugResponse(cheatProbability, expectedProbability);

        // Define behavior of mocked cheaterbugService when analyze is called
        when(cheaterbugService.analyze(requestPayload)).thenReturn(mockResponse);

        // Call the controller method and capture the actual response
        ResponseEntity<CheaterbugResponse> actualResponse = cheaterbugController.analyze(requestPayload);

        // Verify that the service's analyze method was called once with the correct parameter
        verify(cheaterbugService).analyze(requestPayload);

        // Assert the response matches expected mock data
        assertEquals(mockResponse, actualResponse.getBody(), "The response should match the expected response");
        assertEquals(HttpStatus.OK, actualResponse.getStatusCode(), "The HTTP status code should be 200 (OK)");
    }
}