package ai.trustforge.project;
import org.springframework.data.jpa.repository.JpaRepository;
public interface ProjectRepository extends JpaRepository<Project,Long> {
 boolean existsByRepositoryUrl(String repositoryUrl);
}
