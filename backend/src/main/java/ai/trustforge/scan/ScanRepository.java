package ai.trustforge.scan;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
public interface ScanRepository extends JpaRepository<ScanRecord,Long>{List<ScanRecord> findAllByOrderByCreatedAtDesc();}
