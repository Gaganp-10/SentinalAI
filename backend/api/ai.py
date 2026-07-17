import os
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Vulnerability, File, Project, User
from backend.models.schemas import MentorAnswer
from backend.api.auth import get_current_user
from backend.ai.provider import get_ai_provider
from backend.utils.config import settings

router = APIRouter(prefix="/ai", tags=["AI Mentor"])

logger = logging.getLogger(__name__)

class AskMentorRequest(BaseModel):
    vuln_id: UUID
    question: str

@router.post("/ask", response_model=MentorAnswer)
def ask_security_mentor(
    request: AskMentorRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Acts as a 'security mentor' Q&A endpoint.
    Allows developers to ask detailed questions about a specific scan finding,
    leveraging the AI provider with context of the vulnerability and source code.
    """
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
        
    # Read file context from uploads
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
            
    # Get the AI provider and ask the mentor question
    provider = get_ai_provider()
    answer_text = provider.ask_question(
        question=request.question,
        type_name=vuln.type,
        description=vuln.description,
        code_snippet=vuln.code_snippet,
        full_file_source=full_file_content
    )
    
    return MentorAnswer(answer=answer_text)
