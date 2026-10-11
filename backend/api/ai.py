import os
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List, Literal
from pydantic import BaseModel, Field
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Vulnerability, File, Project, User
from backend.models.schemas import MentorAnswer
from backend.api.auth import get_current_user
from backend.ai.provider import get_ai_provider
from backend.utils.config import settings

router = APIRouter(prefix="/ai", tags=["AI Mentor"])

logger = logging.getLogger(__name__)

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str

class AskMentorRequest(BaseModel):
    vuln_id: Optional[UUID] = None
    question: str = Field(..., max_length=2000)
    history: Optional[List[ChatMessage]] = Field(default_factory=list)

@router.post("/ask", response_model=MentorAnswer)
def ask_security_mentor(
    request: AskMentorRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Acts as a 'security mentor' Q&A endpoint.
    For vulnerable_dependency findings: sends only the package line + capped advisory
    summaries (never the manifest/lockfile content).
    For code findings: sends the full file source for context.
    """
    # Fold recent conversation history (last 6 messages max) into question prompt
    folded_question = request.question
    if request.history:
        recent_history = request.history[-6:]
        history_lines = []
        for msg in recent_history:
            role_label = "User" if msg.role == "user" else "Assistant"
            history_lines.append(f"{role_label}: {msg.content.strip()}")
        folded_question = "Previous conversation:\n" + "\n".join(history_lines) + f"\n\nCurrent Question:\n{request.question}"

    provider = get_ai_provider()

    if request.vuln_id:
        # Verify vulnerability ownership
        vuln = db.query(Vulnerability).join(File).join(Project).filter(
            Vulnerability.id == request.vuln_id,
            Project.user_id == current_user.id
        ).first()
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )

        if vuln.type == "vulnerable_dependency":
            # --- Dependency finding: build compact context, never read the manifest file ---
            from backend.sca.findings import build_copilot_context_for_dep

            # Parse advisory details out of the stored recommendation markdown if possible.
            # Fall back to a minimal context derived from description + code_snippet.
            recommended_version: Optional[str] = None
            advisory_details: List[dict] = []

            if vuln.suggested_fix:
                # e.g. "Update requests to >= 2.32.0"
                import re as _re
                m = _re.search(r">=\s*(\S+)", vuln.suggested_fix or "")
                if m:
                    recommended_version = m.group(1)

            # Recover advisory details from recommendation markdown if present
            if vuln.recommendation:
                import re as _re
                for line in vuln.recommendation.splitlines():
                    m_adv = _re.match(
                        r"-\s+\*\*\[(?P<id>[^\]]+)\]\((?P<url>[^\)]*)\)(?:\s+\((?P<cve>[^\)]+)\))?\*\*\s+\[(?P<sev>[^\]]+)\]:\s+(?P<summary>.*?)(?:\s+—\s+Fixed in:\s+`(?P<fixed>[^`]+)`|\s+—\s+No fixed version (?:available|reported))?$",
                        line.strip()
                    )
                    if m_adv:
                        fixed_str = m_adv.group("fixed")
                        fixed_list = [v.strip() for v in fixed_str.split(",")] if fixed_str else []
                        advisory_details.append({
                            "id": m_adv.group("id"),
                            "url": m_adv.group("url"),
                            "cve": m_adv.group("cve"),
                            "severity": m_adv.group("sev"),
                            "summary": m_adv.group("summary").strip(),
                            "fixed": fixed_list
                        })

            # Recover ecosystem + package from recommendation or description
            # The code_snippet stores "name==version" (PyPI) or "name@version (manifest)"
            snippet = vuln.code_snippet or ""
            dep_name = vuln.description.split("'")[1] if "'" in (vuln.description or "") else snippet.split("==")[0].split("@")[0]
            dep_version = vuln.description.split("'")[3] if vuln.description.count("'") >= 4 else ""

            # Determine ecosystem from source_tool or manifest extension
            manifest = vuln.file.filepath if vuln.file else ""
            if manifest.endswith(".txt"):
                ecosystem = "PyPI"
            elif manifest.endswith(".json"):
                ecosystem = "npm"
            elif manifest.endswith(".xml"):
                ecosystem = "Maven"
            else:
                ecosystem = "Unknown"

            copilot_context = build_copilot_context_for_dep(
                dep_name=dep_name,
                dep_version=dep_version,
                ecosystem=ecosystem,
                manifest_file=os.path.basename(manifest),
                recommended_version=recommended_version,
                advisory_details=advisory_details,
            )

            answer_text = provider.ask_question(
                question=folded_question,
                type_name=vuln.type,
                description=vuln.description,
                code_snippet=snippet or None,
                full_file_source=copilot_context
            )
        else:
            # Code finding: read full source file for context
            project_id = vuln.file.project_id
            project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
            full_file_path = os.path.join(project_dir, vuln.file.filepath)
            
            full_file_content = None
            if os.path.exists(full_file_path):
                try:
                    with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                        full_file_content = f.read()
                except Exception as e:
                    logger.warning(f"Could not load full source file for AI mentor: {e}")
                    
            answer_text = provider.ask_question(
                question=folded_question,
                type_name=vuln.type,
                description=vuln.description,
                code_snippet=vuln.code_snippet,
                full_file_source=full_file_content
            )
    else:
        # General application-security inquiry
        answer_text = provider.ask_question(
            question=folded_question,
            type_name="General security question",
            description="",
            code_snippet=None,
            full_file_source=None
        )
        
    return MentorAnswer(answer=answer_text)

