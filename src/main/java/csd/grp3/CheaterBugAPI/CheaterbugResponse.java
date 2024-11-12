package csd.grp3.CheaterBugAPI;

import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CheaterbugResponse {

    private Map<String,String> cheatProbability;
    private Map<String,String> expectedProbability;
}

