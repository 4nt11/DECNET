from fastapi import APIRouter

from .api_get_transcript import router as transcript_router

transcripts_router = APIRouter()
transcripts_router.include_router(transcript_router)
