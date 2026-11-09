package ai.trustforge.scan;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name="scans")
public class ScanRecord {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Column(nullable=false) private Long projectId;
 @Column(nullable=false,length=30) private String status;
 @Column(nullable=false) private Instant createdAt=Instant.now();
 @Column(nullable=false) private Integer findingCount=0;
 @Column(nullable=false) private Integer dependencyCount=0;
 @Column(nullable=false) private Integer riskScore=0;
 @Lob @Column(nullable=false) private String resultJson;
 protected ScanRecord(){}
 public ScanRecord(Long projectId,String status,int findingCount,int dependencyCount,int riskScore,String resultJson){
  this.projectId=projectId;this.status=status;this.findingCount=findingCount;this.dependencyCount=dependencyCount;this.riskScore=riskScore;this.resultJson=resultJson;
 }
 public Long getId(){return id;} public Long getProjectId(){return projectId;} public String getStatus(){return status;}
 public Instant getCreatedAt(){return createdAt;} public Integer getFindingCount(){return findingCount;}
 public Integer getDependencyCount(){return dependencyCount;} public Integer getRiskScore(){return riskScore;}
 public String getResultJson(){return resultJson;}
}
