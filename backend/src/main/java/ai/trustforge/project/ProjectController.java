package ai.trustforge.project;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;
@RestController @RequestMapping("/api/projects")
@CrossOrigin(origins="http://localhost:5173")
public class ProjectController {
 private final ProjectRepository repository;
 public ProjectController(ProjectRepository repository){this.repository=repository;}
 @GetMapping public List<Project> list(){return repository.findAll();}
 @PostMapping @ResponseStatus(HttpStatus.CREATED)
 public Project create(@Valid @RequestBody CreateProjectRequest request){
  String url=request.repositoryUrl().trim().replaceAll("\\.git$","");
  if(!url.matches("^https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$"))
   throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Enter a valid public GitHub repository URL.");
  if(repository.existsByRepositoryUrl(url)) throw new ResponseStatusException(HttpStatus.CONFLICT,"Repository already registered.");
  return repository.save(new Project(request.name().trim(),url));
 }
 @DeleteMapping("/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
 public void delete(@PathVariable Long id){if(!repository.existsById(id))throw new ResponseStatusException(HttpStatus.NOT_FOUND);repository.deleteById(id);}
}
