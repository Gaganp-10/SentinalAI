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
    Allows developers to ask detailed questions about a specific scan finding or general security topics,
    leveraging the AI provider with optional context of the vulnerability and source code.
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
