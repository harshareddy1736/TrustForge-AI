package ai.trustforge.health;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
class HealthControllerTest {
 @Test void healthReportsUp(){var result=new HealthController().health();assertThat(result.get("status")).isEqualTo("UP");}
}
