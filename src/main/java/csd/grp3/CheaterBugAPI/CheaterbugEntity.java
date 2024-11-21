package csd.grp3.CheaterbugAPI;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.DecimalMax;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CheaterbugEntity {

    @DecimalMin(value = "0.0", message = "Expected score must be between 0.0 and 1.0")
    @DecimalMax(value = "1.0", message = "Expected score must be between 0.0 and 1.0")
    private Double expectedScore;

    @NotNull(message = "Actual score must not be null")
    @DecimalMin(value = "0.0", message = "Actual score must be between 0.0 and 1.0")
    @DecimalMax(value = "1.0", message = "Actual score must be between 0.0 and 1.0")
    private Double actualScore;

    public CheaterbugEntity(Double actualScore, Double expectedScore) {
        this.actualScore = actualScore;
        this.expectedScore = expectedScore;
    }

}
