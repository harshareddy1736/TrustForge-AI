from typing import Optional

from fastapi import Body, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from app.scanner import scan_github_repository, make_cyclonedx

app = FastAPI(
    title="TrustForge AI Analysis Service",
    version="1.1.0",
    description="Evidence-first repository dependency, secret-pattern, Dockerfile and advisory analysis. Repository code is never executed."
)

class ScanRequest(BaseModel):
    repository_url: str = Field(min_length=1, max_length=500)

@app.get("/health")
def health():
    return {"status": "UP", "service": "trustforge-analysis", "version": "1.1.0"}

@app.post("/api/v1/scan")
async def scan(
    request: Optional[ScanRequest] = Body(default=None),
    x_repository_url: Optional[str] = Header(default=None, alias="X-Repository-Url"),
):
    # JSON remains the normal public API contract. The header is a compatibility
    # fallback for local JVM clients whose HTTP transport may omit the body.
    repository_url = (
        request.repository_url if request is not None else x_repository_url
    )
    if repository_url is None or not repository_url.strip():
        raise HTTPException(
            status_code=422,
            detail="Provide repository_url in the JSON body or X-Repository-Url header.",
        )

    try:
        return await scan_github_repository(repository_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        # Avoid returning upstream response bodies or internal filesystem details.
        raise HTTPException(status_code=502, detail=f"Repository scan could not be completed ({type(exc).__name__}).")

@app.post("/api/v1/sbom")
async def sbom(request: ScanRequest):
    try:
        result = await scan_github_repository(request.repository_url)
        return make_cyclonedx(result["repository"], result["dependencies"], result.get("findings", []))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"SBOM generation failed ({type(exc).__name__}).")
