package ai.trustforge.project;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name="projects")
public class Project {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Column(nullable=false,length=120) private String name;
 @Column(nullable=false,length=500,unique=true) private String repositoryUrl;
 @Column(nullable=false,length=30) private String provider="GITHUB";
 @Column(nullable=false) private Instant createdAt=Instant.now();
 protected Project(){}
 public Project(String name,String repositoryUrl){this.name=name;this.repositoryUrl=repositoryUrl;}
 public Long getId(){return id;} public String getName(){return name;}
 public String getRepositoryUrl(){return repositoryUrl;} public String getProvider(){return provider;}
 public Instant getCreatedAt(){return createdAt;}
}
