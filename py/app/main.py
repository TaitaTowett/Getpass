from __future__ import annotations

import secrets
import uuid
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.database import create_database_engine, create_session_factory, get_db
from app.models import (
    AuthSession,
    AuditLog,
    Base,
    Facility,
    FacilityProfile,
    GuardianAuthorization,
    ReaderDevice,
    ReaderSubjectLink,
    ReaderVerification,
    ReaderVerificationData,
    ReaderVerificationTarget,
    Student,
    StudentMovement,
    User,
    Visit,
    VisitorDocumentSnapshot,
    VisitPassDetail,
    VisitorFingerprintLink,
    VisitorProfile,
    utc_now,
)
from app.schemas import (
    CheckInRequest,
    CheckOutRequest,
    DemoVerificationRequest,
    FacilityProfileRequest,
    GuardianCreateRequest,
    LoginRequest,
    ReaderCreateRequest,
    ReaderVerificationRequest,
    StaffCreateRequest,
    StudentArrivalRequest,
    StudentCreateRequest,
    StudentDepartureRequest,
)
from app.security import (
    admission_number_lookup_hash,
    decrypt_text,
    document_lookup_hash,
    encrypt_text,
    hash_password,
    keyed_hash,
    new_token,
    verify_password,
)
from app.settings import Settings


ROOT = Path(__file__).resolve().parent.parent
COOKIE_NAME = "gatepass_session"
SESSION_HOURS = 12
VERIFICATION_SECONDS = 45
EAT = timezone(timedelta(hours=3))
DUMMY_PASSWORD_HASH = hash_password("invalid-login-sentinel-value")


@dataclass(frozen=True)
class AuthContext:
    user: User
    facility: Facility
    session: AuthSession


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return _utc(value).isoformat() if value is not None else None


def _public_user(user: User) -> dict[str, object]:
    return {"id": str(user.id), "name": user.full_name, "email": user.email, "role": user.role}


def _audit(
    db: Session,
    facility_id: uuid.UUID,
    action: str,
    actor_user_id: uuid.UUID | None = None,
    reader_id: uuid.UUID | None = None,
    visit_id: uuid.UUID | None = None,
    details: dict[str, object] | None = None,
) -> None:
    db.add(
        AuditLog(
            id=uuid.uuid4(),
            facility_id=facility_id,
            actor_user_id=actor_user_id,
            reader_id=reader_id,
            visit_id=visit_id,
            action=action,
            details=details or {},
        )
    )


def _new_verification(
    db: Session,
    settings: Settings,
    facility_id: uuid.UUID,
    action: Literal["checkin", "checkout", "student_exit"],
    document_type: str,
    document_number: str,
    mode: str,
    reader_id: uuid.UUID | None = None,
    nonce: str | None = None,
) -> ReaderVerification:
    verification = ReaderVerification(
        id=uuid.uuid4(),
        facility_id=facility_id,
        reader_id=reader_id,
        action=action,
        document_type=document_type,
        document_lookup_hash=document_lookup_hash(
            facility_id, document_type, document_number, settings
        ),
        matched=True,
        nonce=nonce or new_token(),
        mode=mode,
        expires_at=utc_now() + timedelta(seconds=VERIFICATION_SECONDS),
    )
    db.add(verification)
    return verification


def _new_visit_verification(
    db: Session,
    facility_id: uuid.UUID,
    visit: Visit,
    mode: str,
    reader_id: uuid.UUID | None = None,
    nonce: str | None = None,
) -> ReaderVerification:
    verification = ReaderVerification(
        id=uuid.uuid4(),
        facility_id=facility_id,
        reader_id=reader_id,
        action="checkout",
        document_type=visit.document_type,
        document_lookup_hash=visit.document_lookup_hash,
        matched=True,
        nonce=nonce or new_token(),
        mode=mode,
        expires_at=utc_now() + timedelta(seconds=VERIFICATION_SECONDS),
    )
    db.add(verification)
    db.add(
        ReaderVerificationTarget(
            verification_id=verification.id,
            facility_id=facility_id,
            visit_id=visit.id,
        )
    )
    return verification


def _reader_subject_hash(
    facility_id: uuid.UUID,
    reader_subject_ref: str,
    settings: Settings,
) -> str:
    return keyed_hash(
        f"{facility_id}:{reader_subject_ref}",
        settings.identifier_hmac_key,
    )


def _ensure_student_admission_schema(engine: Engine) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("students")}
    with engine.begin() as connection:
        if "admission_number_ciphertext" not in columns:
            connection.execute(
                text("ALTER TABLE students ADD COLUMN admission_number_ciphertext TEXT")
            )
        if "admission_number_lookup_hash" not in columns:
            connection.execute(
                text("ALTER TABLE students ADD COLUMN admission_number_lookup_hash VARCHAR(64)")
            )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_student_facility_admission_number "
                "ON students (facility_id, admission_number_lookup_hash)"
            )
        )


def _visitor_document_number_for_visit(
    db: Session,
    visit: Visit,
    settings: Settings,
) -> str | None:
    snapshot = db.get(VisitorDocumentSnapshot, visit.id)
    if snapshot is None:
        return None
    return decrypt_text(snapshot.document_number_ciphertext, settings)


def _upsert_visitor_profile(
    db: Session,
    facility_id: uuid.UUID,
    document_type: str,
    document_number: str,
    identity_hash: str,
    full_name: str,
    phone: str,
    verification: ReaderVerification,
    settings: Settings,
) -> VisitorProfile:
    profile = db.scalar(
        select(VisitorProfile)
        .where(
            VisitorProfile.facility_id == facility_id,
            VisitorProfile.document_type == document_type,
            VisitorProfile.document_lookup_hash == identity_hash,
        )
        .with_for_update()
    )
    if profile is None:
        profile = VisitorProfile(
            id=uuid.uuid4(),
            facility_id=facility_id,
            document_type=document_type,
            document_lookup_hash=identity_hash,
            full_name_ciphertext=_encrypt_required(full_name, settings),
            document_number_ciphertext=_encrypt_required(document_number, settings),
            phone_ciphertext=encrypt_text(phone.strip() or None, settings),
        )
        db.add(profile)
        db.flush()
    else:
        profile.full_name_ciphertext = _encrypt_required(full_name, settings)
        profile.document_number_ciphertext = _encrypt_required(document_number, settings)
        profile.phone_ciphertext = encrypt_text(phone.strip() or None, settings)

    scan_data = db.get(ReaderVerificationData, verification.id)
    if scan_data is not None and scan_data.subject_lookup_hash is not None:
        fingerprint_link = db.scalar(
            select(VisitorFingerprintLink)
            .where(
                VisitorFingerprintLink.facility_id == facility_id,
                VisitorFingerprintLink.subject_lookup_hash == scan_data.subject_lookup_hash,
            )
            .with_for_update()
        )
        if fingerprint_link is None:
            fingerprint_link = VisitorFingerprintLink(
                id=uuid.uuid4(),
                facility_id=facility_id,
                visitor_profile_id=profile.id,
                subject_lookup_hash=scan_data.subject_lookup_hash,
                reader_id=verification.reader_id,
            )
            db.add(fingerprint_link)
        else:
            fingerprint_link.visitor_profile_id = profile.id
            fingerprint_link.reader_id = verification.reader_id
    return profile


def _create_repeat_fingerprint_visit(
    db: Session,
    settings: Settings,
    facility_id: uuid.UUID,
    reader_id: uuid.UUID | None,
    reader_subject_ref: str,
    nonce: str,
    mode: str,
    matched: bool = True,
) -> dict[str, object]:
    now = utc_now()
    subject_hash = _reader_subject_hash(facility_id, reader_subject_ref, settings)
    if not matched:
        db.add(
            ReaderVerification(
                id=uuid.uuid4(),
                facility_id=facility_id,
                reader_id=reader_id,
                action="repeat_checkin",
                document_type="Fingerprint",
                document_lookup_hash=subject_hash,
                matched=False,
                nonce=nonce,
                mode=mode,
                expires_at=now + timedelta(seconds=VERIFICATION_SECONDS),
            )
        )
        _audit(db, facility_id, "reader_match_failed", reader_id=reader_id, details={"action": "repeat_checkin"})
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Reader nonce was already used.") from exc
        raise HTTPException(status_code=403, detail="Reader did not verify the returning visitor.")

    fingerprint_link = db.scalar(
        select(VisitorFingerprintLink).where(
            VisitorFingerprintLink.facility_id == facility_id,
            VisitorFingerprintLink.subject_lookup_hash == subject_hash,
        )
    )
    if fingerprint_link is None:
        raise HTTPException(
            status_code=404,
            detail="No visitor profile is enrolled for this fingerprint. Scan the visitor's ID first.",
        )
    profile = db.scalar(
        select(VisitorProfile).where(
            VisitorProfile.id == fingerprint_link.visitor_profile_id,
            VisitorProfile.facility_id == facility_id,
        )
    )
    if profile is None:
        raise HTTPException(status_code=404, detail="The visitor profile for this fingerprint is unavailable.")

    verification = ReaderVerification(
        id=uuid.uuid4(),
        facility_id=facility_id,
        reader_id=reader_id,
        action="repeat_checkin",
        document_type=profile.document_type,
        document_lookup_hash=profile.document_lookup_hash,
        matched=True,
        nonce=nonce,
        mode=mode,
        expires_at=now + timedelta(seconds=VERIFICATION_SECONDS),
        consumed_at=now,
    )
    db.add(verification)
    active_visit = db.scalar(
        select(Visit)
        .where(
            Visit.facility_id == facility_id,
            Visit.document_type == profile.document_type,
            Visit.document_lookup_hash == profile.document_lookup_hash,
            Visit.checked_out_at.is_(None),
        )
        .with_for_update()
    )
    if active_visit is not None:
        _audit(
            db,
            facility_id,
            "repeat_fingerprint_checkin_blocked",
            reader_id=reader_id,
            visit_id=active_visit.id,
        )
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Reader nonce was already used.") from exc
        raise HTTPException(status_code=409, detail="This visitor is already checked in.")

    document_number = decrypt_text(profile.document_number_ciphertext, settings)
    if document_number is None:
        raise RuntimeError("The visitor profile has no encrypted document number.")
    normalized_document = "".join(
        character
        for character in document_number.upper()
        if character not in " -\t\r\n"
    )
    visit = Visit(
        id=uuid.uuid4(),
        facility_id=facility_id,
        full_name_ciphertext=profile.full_name_ciphertext,
        document_type=profile.document_type,
        document_lookup_hash=profile.document_lookup_hash,
        document_last_four=normalized_document[-4:],
        phone_ciphertext=profile.phone_ciphertext,
        host_ciphertext=_encrypt_required("Not specified", settings),
        purpose_ciphertext=_encrypt_required("Repeat visitor fingerprint check-in", settings),
        checked_in_at=now,
        checkin_verification_id=verification.id,
    )
    db.add(visit)
    db.add(VisitPassDetail(visit_id=visit.id, pass_type="general"))
    db.add(
        VisitorDocumentSnapshot(
            visit_id=visit.id,
            document_number_ciphertext=profile.document_number_ciphertext,
        )
    )
    if reader_id is not None:
        subject_link = db.scalar(
            select(ReaderSubjectLink)
            .where(
                ReaderSubjectLink.facility_id == facility_id,
                ReaderSubjectLink.subject_lookup_hash == subject_hash,
            )
            .with_for_update()
        )
        if subject_link is None:
            subject_link = ReaderSubjectLink(
                id=uuid.uuid4(),
                facility_id=facility_id,
                reader_id=reader_id,
                checkin_verification_id=verification.id,
                subject_lookup_hash=subject_hash,
            )
            db.add(subject_link)
        else:
            subject_link.reader_id = reader_id
            subject_link.checkin_verification_id = verification.id
        fingerprint_link.reader_id = reader_id
    _audit(
        db,
        facility_id,
        "visitor_repeat_fingerprint_checkin",
        reader_id=reader_id,
        visit_id=visit.id,
        details={"verification_mode": mode, "visitor_type": "general"},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="This visitor already has an active visit.") from exc
    return {
        "visit_id": str(visit.id),
        "status": "checked_in",
        "checked_in_at": _iso(visit.checked_in_at),
    }


def _consume_verification(
    db: Session,
    settings: Settings,
    facility_id: uuid.UUID,
    action: Literal["checkin", "checkout", "student_exit"],
    document_type: str,
    document_number: str,
    verification_id: uuid.UUID,
) -> ReaderVerification:
    identity_hash = document_lookup_hash(
        facility_id, document_type, document_number, settings
    )
    verification = db.scalar(
        select(ReaderVerification)
        .where(
            ReaderVerification.id == verification_id,
            ReaderVerification.facility_id == facility_id,
            ReaderVerification.action == action,
            ReaderVerification.document_type == document_type,
            ReaderVerification.document_lookup_hash == identity_hash,
            ReaderVerification.matched.is_(True),
            ReaderVerification.consumed_at.is_(None),
        )
        .with_for_update()
    )
    if verification is None or _utc(verification.expires_at) <= utc_now():
        raise HTTPException(
            status_code=403,
            detail="Reader verification is missing, expired, already used, or does not match this visitor.",
        )
    verification.consumed_at = utc_now()
    return verification


def _consume_visit_verification(
    db: Session,
    facility_id: uuid.UUID,
    visit: Visit,
    verification_id: uuid.UUID,
) -> ReaderVerification:
    verification = db.scalar(
        select(ReaderVerification)
        .join(
            ReaderVerificationTarget,
            ReaderVerificationTarget.verification_id == ReaderVerification.id,
        )
        .where(
            ReaderVerification.id == verification_id,
            ReaderVerification.facility_id == facility_id,
            ReaderVerificationTarget.facility_id == facility_id,
            ReaderVerificationTarget.visit_id == visit.id,
            ReaderVerification.action == "checkout",
            ReaderVerification.document_type == visit.document_type,
            ReaderVerification.document_lookup_hash == visit.document_lookup_hash,
            ReaderVerification.matched.is_(True),
            ReaderVerification.consumed_at.is_(None),
        )
        .with_for_update()
    )
    if verification is None or _utc(verification.expires_at) <= utc_now():
        raise HTTPException(
            status_code=403,
            detail="Fingerprint verification is missing, expired, already used, or does not match this visit.",
        )
    verification.consumed_at = utc_now()
    return verification


def _visit_response(
    visit: Visit,
    settings: Settings,
    visitor_type: str = "general",
    document_number: str | None = None,
    reveal_document_number: bool = False,
) -> dict[str, object]:
    return {
        "id": str(visit.id),
        "full_name": decrypt_text(visit.full_name_ciphertext, settings),
        "visitor_type": visitor_type,
        "document_type": visit.document_type,
        "document": f"{visit.document_type} ••••{visit.document_last_four}",
        "document_number": (
            document_number if reveal_document_number else None
        ),
        "host": decrypt_text(visit.host_ciphertext, settings),
        "purpose": decrypt_text(visit.purpose_ciphertext, settings),
        "checked_in_at": _iso(visit.checked_in_at),
        "checked_out_at": _iso(visit.checked_out_at),
    }


def _facility_type(db: Session, facility_id: uuid.UUID) -> str:
    profile = db.get(FacilityProfile, facility_id)
    if profile is None:
        return "public_ministry"
    legacy_types = {
        "public_facility": "public_ministry",
        "school": "public_school",
        "mixed": "public_school",
    }
    return legacy_types.get(profile.facility_type, profile.facility_type)


def _require_school_facility(db: Session, facility_id: uuid.UUID) -> None:
    if _facility_type(db, facility_id) not in {"public_school", "private_school"}:
        raise HTTPException(status_code=404, detail="School movement workflows are not enabled for this facility.")


def _student_response(
    student: Student,
    guardians: list[GuardianAuthorization],
    settings: Settings,
    session_status: str = "checked_out",
    last_movement_at: datetime | None = None,
) -> dict[str, object]:
    return {
        "id": str(student.id),
        "full_name": decrypt_text(student.full_name_ciphertext, settings),
        "class_name": decrypt_text(student.class_ciphertext, settings),
        "admission_number": decrypt_text(student.admission_number_ciphertext, settings),
        "session_status": session_status,
        "last_movement_at": _iso(last_movement_at) if last_movement_at else None,
        "guardians": [
            {
                "id": str(guardian.id),
                "full_name": decrypt_text(guardian.full_name_ciphertext, settings),
                "relationship": decrypt_text(guardian.relationship_ciphertext, settings),
                "document": f"{guardian.document_type} ••••{guardian.document_last_four}",
            }
            for guardian in guardians
            if guardian.is_active
        ],
    }


def _encrypt_required(value: str, settings: Settings) -> str:
    encrypted = encrypt_text(value, settings)
    if encrypted is None:
        raise RuntimeError("Required personal data was not encrypted.")
    return encrypted


def _student_movement_response(
    movement: StudentMovement,
    student: Student,
    guardian: GuardianAuthorization | None,
    user: User | None,
    settings: Settings,
) -> dict[str, object]:
    details = decrypt_text(movement.details_ciphertext, settings)
    return {
        "id": str(movement.id),
        "student_name": decrypt_text(student.full_name_ciphertext, settings),
        "class_name": decrypt_text(student.class_ciphertext, settings),
        "admission_number": decrypt_text(student.admission_number_ciphertext, settings),
        "movement_type": movement.movement_type,
        "guardian_name": (
            decrypt_text(guardian.full_name_ciphertext, settings) if guardian is not None else None
        ),
        "recorded_by": user.full_name if user is not None else "Former staff account",
        "release_approved": movement.release_approved,
        "details": json.loads(details) if details else {},
        "created_at": _iso(movement.created_at),
    }


def _current_auth(request: Request, db: Session) -> AuthContext:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    settings: Settings = request.app.state.settings
    token_digest = keyed_hash(token, settings.session_hmac_key)
    session = db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == token_digest,
            AuthSession.revoked_at.is_(None),
        )
    )
    if session is None or _utc(session.expires_at) <= utc_now():
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="This staff account is inactive.")
    facility = db.get(Facility, user.facility_id)
    if facility is None:
        raise HTTPException(status_code=401, detail="This facility account is unavailable.")
    return AuthContext(user=user, facility=facility, session=session)


def _require_csrf(request: Request, auth: AuthContext) -> None:
    provided = request.headers.get("X-CSRF-Token", "")
    settings: Settings = request.app.state.settings
    provided_digest = keyed_hash(provided, settings.session_hmac_key)
    if not provided or not secrets.compare_digest(provided_digest, auth.session.csrf_hash):
        raise HTTPException(status_code=403, detail="CSRF validation failed. Refresh your session.")


def _require_role(auth: AuthContext, *roles: str) -> None:
    if auth.user.role not in roles:
        raise HTTPException(status_code=403, detail="Your staff role cannot perform this action.")


def create_app(
    settings: Settings | None = None,
    engine=None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = engine or create_database_engine(settings.database_url)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        Base.metadata.create_all(bind=engine)
        _ensure_student_admission_schema(engine)
        yield

    app = FastAPI(
        title="GatePass Gate Operations API",
        version="1.0.0",
        docs_url=None if settings.app_env == "production" else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.app_env == "production" else "/api/openapi.json",
        lifespan=lifespan,
    )
    if settings.app_env == "production":
        if not settings.trusted_hosts or "*" in settings.trusted_hosts:
            raise RuntimeError("Production requires explicit trusted hosts.")
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=list(settings.trusted_hosts),
        )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                body_size = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid request length."})
            if body_size > 16_384:
                return JSONResponse(status_code=413, content={"detail": "Request body exceeds 16 KB."})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.get("/", include_in_schema=False)
    def home() -> FileResponse:
        return FileResponse(ROOT / "index.html", media_type="text/html")

    @app.get("/hardware-design", include_in_schema=False)
    def hardware_design() -> FileResponse:
        return FileResponse(ROOT / "hardware-design.html", media_type="text/html")

    @app.get("/hardware-design.pdf", include_in_schema=False)
    def hardware_design_pdf() -> FileResponse:
        return FileResponse(
            ROOT / "hardware-design.pdf",
            media_type="application/pdf",
            filename="GETPASS-Hardware-Concept-Nov-2026.pdf",
        )

    @app.get("/api/health/live")
    def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/health/ready")
    def health_ready(db: Session = Depends(get_db)) -> dict[str, str]:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}

    @app.get("/api/config")
    def public_config() -> dict[str, str]:
        return {"reader_mode": settings.reader_mode, "environment": settings.app_env}

    @app.post("/api/auth/login")
    def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
        facility = db.scalar(select(Facility).where(Facility.slug == payload.facility_slug))
        if facility is None:
            verify_password(payload.password, DUMMY_PASSWORD_HASH)
            raise HTTPException(status_code=401, detail="Facility, email, or password is incorrect.")
        facility_type_matches = (
            payload.facility_type is None
            or payload.facility_type == _facility_type(db, facility.id)
        )
        user = db.scalar(
            select(User).where(
                User.facility_id == facility.id,
                User.email == payload.email,
            )
        )
        if user is None or not facility_type_matches:
            verify_password(payload.password, DUMMY_PASSWORD_HASH)
            raise HTTPException(status_code=401, detail="Facility, email, or password is incorrect.")
        password_valid = verify_password(payload.password, user.password_hash)
        now = utc_now()
        locked = (
            user.locked_until is not None
            and _utc(user.locked_until) > now
        )
        if not user.is_active or not password_valid or locked:
            if not locked:
                user.failed_login_count += 1
                if user.failed_login_count >= 5:
                    user.locked_until = now + timedelta(minutes=15)
                db.commit()
            raise HTTPException(status_code=401, detail="Facility, email, or password is incorrect.")

        user.failed_login_count = 0
        user.locked_until = None
        session_token = new_token()
        csrf_token = new_token()
        auth_session = AuthSession(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=keyed_hash(session_token, settings.session_hmac_key),
            csrf_hash=keyed_hash(csrf_token, settings.session_hmac_key),
            expires_at=now + timedelta(hours=SESSION_HOURS),
        )
        db.add(auth_session)
        _audit(db, facility.id, "staff_login", actor_user_id=user.id)
        db.commit()
        response.set_cookie(
            COOKIE_NAME,
            session_token,
            max_age=SESSION_HOURS * 60 * 60,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            path="/",
        )
        return {
            "csrf_token": csrf_token,
            "user": _public_user(user),
            "facility": {
                "slug": facility.slug,
                "name": facility.name,
                "facility_type": _facility_type(db, facility.id),
            },
        }

    @app.get("/api/auth/session", response_model=None)
    def session_info(
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object] | Response:
        if not request.cookies.get(COOKIE_NAME):
            return Response(status_code=204)
        auth = _current_auth(request, db)
        csrf_token = new_token()
        auth.session.csrf_hash = keyed_hash(csrf_token, settings.session_hmac_key)
        db.commit()
        return {
            "csrf_token": csrf_token,
            "user": _public_user(auth.user),
            "facility": {
                "slug": auth.facility.slug,
                "name": auth.facility.name,
                "facility_type": _facility_type(db, auth.facility.id),
            },
        }

    @app.post("/api/auth/logout")
    def logout(
        request: Request,
        response: Response,
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        auth.session.revoked_at = utc_now()
        _audit(db, auth.facility.id, "staff_logout", actor_user_id=auth.user.id)
        db.commit()
        response.delete_cookie(
            COOKIE_NAME,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            path="/",
        )
        return {"message": "Signed out."}

    @app.post("/api/staff", status_code=201)
    def create_staff(
        payload: StaffCreateRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        user = User(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            email=payload.email,
            full_name=payload.full_name,
            role=payload.role,
            password_hash=hash_password(payload.password),
        )
        db.add(user)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="That email already has an account at this facility.") from exc
        _audit(
            db,
            auth.facility.id,
            "staff_account_created",
            actor_user_id=auth.user.id,
            details={"role": user.role},
        )
        db.commit()
        return _public_user(user)

    @app.get("/api/staff")
    def list_staff(
        request: Request,
        db: Session = Depends(get_db),
    ) -> list[dict[str, object]]:
        auth = _current_auth(request, db)
        _require_role(auth, "facility_admin")
        users = db.scalars(
            select(User)
            .where(User.facility_id == auth.facility.id)
            .order_by(User.full_name)
        ).all()
        return [
            {**_public_user(user), "is_active": user.is_active}
            for user in users
        ]

    @app.put("/api/facility/profile")
    def update_facility_profile(
        payload: FacilityProfileRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        profile = db.get(FacilityProfile, auth.facility.id)
        if profile is None:
            profile = FacilityProfile(
                facility_id=auth.facility.id,
                facility_type=payload.facility_type,
            )
            db.add(profile)
        else:
            profile.facility_type = payload.facility_type
        _audit(
            db,
            auth.facility.id,
            "facility_type_updated",
            actor_user_id=auth.user.id,
            details={"facility_type": payload.facility_type},
        )
        db.commit()
        return {"facility_type": profile.facility_type}

    @app.get("/api/students")
    def list_students(
        request: Request,
        db: Session = Depends(get_db),
    ) -> list[dict[str, object]]:
        auth = _current_auth(request, db)
        _require_school_facility(db, auth.facility.id)
        students = db.scalars(
            select(Student)
            .where(Student.facility_id == auth.facility.id, Student.is_active.is_(True))
            .order_by(Student.created_at.desc())
            .limit(500)
        ).all()
        student_ids = [student.id for student in students]
        guardians = db.scalars(
            select(GuardianAuthorization)
            .where(
                GuardianAuthorization.facility_id == auth.facility.id,
                GuardianAuthorization.student_id.in_(student_ids),
                GuardianAuthorization.is_active.is_(True),
            )
            .order_by(GuardianAuthorization.created_at)
        ).all()
        guardians_by_student: dict[uuid.UUID, list[GuardianAuthorization]] = {}
        for guardian in guardians:
            guardians_by_student.setdefault(guardian.student_id, []).append(guardian)
        latest_movements = (
            select(
                StudentMovement.student_id.label("student_id"),
                StudentMovement.movement_type.label("movement_type"),
                StudentMovement.created_at.label("created_at"),
                func.row_number()
                .over(
                    partition_by=StudentMovement.student_id,
                    order_by=(StudentMovement.created_at.desc(), StudentMovement.id.desc()),
                )
                .label("position"),
            )
            .where(
                StudentMovement.facility_id == auth.facility.id,
                StudentMovement.student_id.in_(student_ids),
            )
            .subquery()
        )
        movement_by_student = {
            row.student_id: (row.movement_type, row.created_at)
            for row in db.execute(
                select(
                    latest_movements.c.student_id,
                    latest_movements.c.movement_type,
                    latest_movements.c.created_at,
                ).where(latest_movements.c.position == 1)
            )
        }
        responses = []
        for student in students:
            latest_movement = movement_by_student.get(student.id)
            session_status = (
                "in_session"
                if latest_movement is not None and latest_movement[0] == "arrival"
                else "checked_out"
            )
            last_movement_at = latest_movement[1] if latest_movement is not None else None
            responses.append(
                _student_response(
                    student,
                    guardians_by_student.get(student.id, []),
                    settings,
                    session_status,
                    last_movement_at,
                )
            )
        return responses

    @app.post("/api/students", status_code=201)
    def create_student(
        payload: StudentCreateRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        _require_school_facility(db, auth.facility.id)
        try:
            admission_hash = admission_number_lookup_hash(
                auth.facility.id, payload.admission_number, settings
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        student = Student(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            full_name_ciphertext=_encrypt_required(payload.full_name, settings),
            class_ciphertext=_encrypt_required(payload.class_name, settings),
            admission_number_ciphertext=_encrypt_required(payload.admission_number, settings),
            admission_number_lookup_hash=admission_hash,
        )
        db.add(student)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="That admission or registration number is already on this school's roster.",
            ) from exc
        _audit(
            db,
            auth.facility.id,
            "student_added_to_roster",
            actor_user_id=auth.user.id,
            details={"student_id": str(student.id)},
        )
        db.commit()
        return _student_response(student, [], settings)

    @app.post("/api/students/{student_id}/guardians", status_code=201)
    def authorize_guardian(
        student_id: uuid.UUID,
        payload: GuardianCreateRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        _require_school_facility(db, auth.facility.id)
        student = db.scalar(
            select(Student).where(
                Student.id == student_id,
                Student.facility_id == auth.facility.id,
                Student.is_active.is_(True),
            )
        )
        if student is None:
            raise HTTPException(status_code=404, detail="Student not found.")
        try:
            lookup_hash = document_lookup_hash(
                auth.facility.id, payload.document_type, payload.document_number, settings
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        normalized_document = "".join(
            character
            for character in payload.document_number.upper()
            if character not in " -\t\r\n"
        )
        guardian = db.scalar(
            select(GuardianAuthorization)
            .where(
                GuardianAuthorization.facility_id == auth.facility.id,
                GuardianAuthorization.student_id == student.id,
                GuardianAuthorization.document_type == payload.document_type,
                GuardianAuthorization.document_lookup_hash == lookup_hash,
            )
            .with_for_update()
        )
        if guardian is not None and guardian.is_active:
            raise HTTPException(
                status_code=409,
                detail="That ID or passport is already authorized for this student.",
            )
        reactivated = guardian is not None
        if guardian is None:
            guardian = GuardianAuthorization(
                id=uuid.uuid4(),
                facility_id=auth.facility.id,
                student_id=student.id,
                full_name_ciphertext=_encrypt_required(payload.full_name, settings),
                document_type=payload.document_type,
                document_lookup_hash=lookup_hash,
                document_last_four=normalized_document[-4:],
                relationship_ciphertext=_encrypt_required(payload.relationship, settings),
            )
            db.add(guardian)
        else:
            guardian.full_name_ciphertext = _encrypt_required(payload.full_name, settings)
            guardian.document_last_four = normalized_document[-4:]
            guardian.relationship_ciphertext = _encrypt_required(payload.relationship, settings)
            guardian.is_active = True
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="That ID or passport is already authorized for this student.",
            ) from exc
        _audit(
            db,
            auth.facility.id,
            (
                "guardian_authorization_reactivated"
                if reactivated
                else "guardian_authorized_for_student"
            ),
            actor_user_id=auth.user.id,
            details={"student_id": str(student.id), "guardian_id": str(guardian.id)},
        )
        db.commit()
        return {
            "id": str(guardian.id),
            "student_id": str(student.id),
            "full_name": decrypt_text(guardian.full_name_ciphertext, settings),
            "relationship": decrypt_text(guardian.relationship_ciphertext, settings),
            "document": f"{guardian.document_type} ••••{guardian.document_last_four}",
        }

    @app.delete("/api/guardians/{guardian_id}", status_code=204)
    def revoke_guardian(
        guardian_id: uuid.UUID,
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        _require_school_facility(db, auth.facility.id)
        guardian = db.scalar(
            select(GuardianAuthorization).where(
                GuardianAuthorization.id == guardian_id,
                GuardianAuthorization.facility_id == auth.facility.id,
            )
        )
        if guardian is None:
            raise HTTPException(status_code=404, detail="Guardian authorization not found.")
        guardian.is_active = False
        _audit(
            db,
            auth.facility.id,
            "guardian_authorization_revoked",
            actor_user_id=auth.user.id,
            details={
                "student_id": str(guardian.student_id),
                "guardian_id": str(guardian.id),
            },
        )
        db.commit()
        return Response(status_code=204)

    @app.post("/api/students/{student_id}/arrivals", status_code=201)
    def record_student_arrival(
        student_id: uuid.UUID,
        payload: StudentArrivalRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin", "operator")
        _require_school_facility(db, auth.facility.id)
        student = db.scalar(
            select(Student).where(
                Student.id == student_id,
                Student.facility_id == auth.facility.id,
                Student.is_active.is_(True),
            )
        )
        if student is None:
            raise HTTPException(status_code=404, detail="Student not found.")
        details = json.dumps(
            {
                "arrival_context": payload.arrival_context,
                "accompanied_by": payload.accompanied_by,
                "note": payload.note,
            }
        )
        movement = StudentMovement(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            student_id=student.id,
            recorded_by_user_id=auth.user.id,
            movement_type="arrival",
            details_ciphertext=_encrypt_required(details, settings),
        )
        db.add(movement)
        _audit(
            db,
            auth.facility.id,
            "student_arrival_recorded",
            actor_user_id=auth.user.id,
            details={"student_id": str(student.id), "arrival_context": payload.arrival_context},
        )
        db.commit()
        return _student_movement_response(movement, student, None, auth.user, settings)

    @app.post("/api/students/{student_id}/departures", status_code=201)
    def approve_student_departure(
        student_id: uuid.UUID,
        payload: StudentDepartureRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin", "operator")
        _require_school_facility(db, auth.facility.id)
        if not payload.operator_approved:
            raise HTTPException(
                status_code=403,
                detail="A gate operator must explicitly approve each student release.",
            )
        student = db.scalar(
            select(Student).where(
                Student.id == student_id,
                Student.facility_id == auth.facility.id,
                Student.is_active.is_(True),
            )
        )
        if student is None:
            raise HTTPException(status_code=404, detail="Student not found.")
        try:
            lookup_hash = document_lookup_hash(
                auth.facility.id, payload.document_type, payload.document_number, settings
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        guardian = db.scalar(
            select(GuardianAuthorization).where(
                GuardianAuthorization.facility_id == auth.facility.id,
                GuardianAuthorization.student_id == student.id,
                GuardianAuthorization.document_type == payload.document_type,
                GuardianAuthorization.document_lookup_hash == lookup_hash,
                GuardianAuthorization.is_active.is_(True),
            ).with_for_update()
        )
        if guardian is None:
            raise HTTPException(
                status_code=403,
                detail="This adult is not on the student's active authorized-guardian roster.",
            )
        verification = _consume_verification(
            db,
            settings,
            auth.facility.id,
            "student_exit",
            payload.document_type,
            payload.document_number,
            payload.verification_id,
        )
        movement = StudentMovement(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            student_id=student.id,
            guardian_id=guardian.id,
            verification_id=verification.id,
            recorded_by_user_id=auth.user.id,
            movement_type="departure",
            release_approved=True,
            details_ciphertext=_encrypt_required(json.dumps({"note": payload.note}), settings),
        )
        db.add(movement)
        _audit(
            db,
            auth.facility.id,
            "student_departure_approved",
            actor_user_id=auth.user.id,
            reader_id=verification.reader_id,
            details={
                "verification_mode": verification.mode,
                "student_id": str(student.id),
                "guardian_id": str(guardian.id),
            },
        )
        db.commit()
        return _student_movement_response(movement, student, guardian, auth.user, settings)

    @app.get("/api/students/movements")
    def list_student_movements(
        request: Request,
        db: Session = Depends(get_db),
    ) -> list[dict[str, object]]:
        auth = _current_auth(request, db)
        _require_school_facility(db, auth.facility.id)
        movements = db.scalars(
            select(StudentMovement)
            .where(StudentMovement.facility_id == auth.facility.id)
            .order_by(StudentMovement.created_at.desc())
            .limit(100)
        ).all()
        student_ids = {movement.student_id for movement in movements}
        guardian_ids = {
            movement.guardian_id for movement in movements if movement.guardian_id is not None
        }
        user_ids = {movement.recorded_by_user_id for movement in movements}
        students = {
            student.id: student
            for student in db.scalars(select(Student).where(Student.id.in_(student_ids))).all()
        }
        guardians = {
            guardian.id: guardian
            for guardian in db.scalars(
                select(GuardianAuthorization).where(GuardianAuthorization.id.in_(guardian_ids))
            ).all()
        }
        users = {
            user.id: user
            for user in db.scalars(select(User).where(User.id.in_(user_ids))).all()
        }
        return [
            _student_movement_response(
                movement,
                students[movement.student_id],
                (
                    guardians.get(movement.guardian_id)
                    if movement.guardian_id is not None
                    else None
                ),
                users.get(movement.recorded_by_user_id),
                settings,
            )
            for movement in movements
            if movement.student_id in students
        ]

    @app.post("/api/readers", status_code=201)
    def create_reader(
        payload: ReaderCreateRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        token = new_token()
        reader = ReaderDevice(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            label=payload.label,
            token_hash=keyed_hash(token, settings.session_hmac_key),
        )
        db.add(reader)
        _audit(
            db,
            auth.facility.id,
            "reader_created",
            actor_user_id=auth.user.id,
            reader_id=reader.id,
        )
        db.commit()
        return {"id": str(reader.id), "label": reader.label, "reader_token": token}

    @app.get("/api/readers")
    def list_readers(
        request: Request,
        db: Session = Depends(get_db),
    ) -> list[dict[str, object]]:
        auth = _current_auth(request, db)
        _require_role(auth, "facility_admin")
        readers = db.scalars(
            select(ReaderDevice)
            .where(ReaderDevice.facility_id == auth.facility.id)
            .order_by(ReaderDevice.created_at.desc())
        ).all()
        return [
            {
                "id": str(reader.id),
                "label": reader.label,
                "is_active": reader.is_active,
                "last_seen_at": _iso(reader.last_seen_at),
            }
            for reader in readers
        ]

    @app.delete("/api/readers/{reader_id}", status_code=204)
    def revoke_reader(
        reader_id: uuid.UUID,
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin")
        reader = db.scalar(
            select(ReaderDevice).where(
                ReaderDevice.id == reader_id,
                ReaderDevice.facility_id == auth.facility.id,
            )
        )
        if reader is None:
            raise HTTPException(status_code=404, detail="Reader not found.")
        reader.is_active = False
        _audit(
            db,
            auth.facility.id,
            "reader_revoked",
            actor_user_id=auth.user.id,
            reader_id=reader.id,
        )
        db.commit()
        return Response(status_code=204)

    @app.post("/api/reader/verifications", status_code=201)
    def submit_reader_verification(
        payload: ReaderVerificationRequest,
        reader_token: str | None = Header(default=None, alias="X-Reader-Token"),
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        if not reader_token:
            raise HTTPException(status_code=401, detail="Reader authentication is required.")
        token_hash = keyed_hash(reader_token, settings.session_hmac_key)
        reader = db.scalar(
            select(ReaderDevice).where(
                ReaderDevice.token_hash == token_hash,
                ReaderDevice.is_active.is_(True),
            )
        )
        if reader is None:
            raise HTTPException(status_code=401, detail="Reader authentication failed.")
        now = utc_now()
        reader.last_seen_at = now
        if payload.action == "repeat_checkin":
            if payload.reader_subject_ref is None:
                raise HTTPException(status_code=422, detail="The reader subject reference is required.")
            return _create_repeat_fingerprint_visit(
                db,
                settings,
                reader.facility_id,
                reader.id,
                payload.reader_subject_ref,
                payload.nonce,
                mode="device",
                matched=payload.matched,
            )
        checkout_visit: Visit | None = None
        if payload.action == "checkout":
            if payload.visit_id is not None:
                checkout_visit = db.scalar(
                    select(Visit)
                    .join(
                        ReaderSubjectLink,
                        ReaderSubjectLink.checkin_verification_id
                        == Visit.checkin_verification_id,
                    )
                    .where(
                        Visit.id == payload.visit_id,
                        Visit.facility_id == reader.facility_id,
                        Visit.checked_out_at.is_(None),
                        ReaderSubjectLink.facility_id == reader.facility_id,
                    )
                )
            else:
                if payload.reader_subject_ref is None:
                    raise HTTPException(
                        status_code=422,
                        detail="The reader subject reference is required for fingerprint checkout.",
                    )
                subject_hash = _reader_subject_hash(
                    reader.facility_id, payload.reader_subject_ref, settings
                )
                checkout_visit = db.scalar(
                    select(Visit)
                    .join(
                        ReaderSubjectLink,
                        ReaderSubjectLink.checkin_verification_id
                        == Visit.checkin_verification_id,
                    )
                    .where(
                        Visit.facility_id == reader.facility_id,
                        Visit.checked_out_at.is_(None),
                        ReaderSubjectLink.facility_id == reader.facility_id,
                        ReaderSubjectLink.subject_lookup_hash == subject_hash,
                    )
                )
            if checkout_visit is None:
                raise HTTPException(
                    status_code=404,
                    detail="No active fingerprint-enrolled visit matches this reader result.",
                )
            document_type = checkout_visit.document_type
            identity_hash = checkout_visit.document_lookup_hash
        else:
            if payload.document_type is None or payload.document_number is None:
                raise HTTPException(status_code=422, detail="The reader did not provide the scanned document.")
            document_type = payload.document_type
            identity_hash = document_lookup_hash(
                reader.facility_id, document_type, payload.document_number, settings
            )
        verification = ReaderVerification(
            id=uuid.uuid4(),
            facility_id=reader.facility_id,
            reader_id=reader.id,
            action=payload.action,
            document_type=document_type,
            document_lookup_hash=identity_hash,
            matched=payload.matched,
            nonce=payload.nonce,
            mode="device",
            expires_at=now + timedelta(seconds=VERIFICATION_SECONDS),
        )
        db.add(verification)
        if not payload.matched:
            _audit(
                db,
                reader.facility_id,
                "reader_match_failed",
                reader_id=reader.id,
                details={"action": payload.action},
            )
            try:
                db.commit()
            except IntegrityError as exc:
                db.rollback()
                raise HTTPException(status_code=409, detail="Reader nonce was already used.") from exc
            raise HTTPException(status_code=403, detail="Reader did not verify the visitor.")
        try:
            if payload.action == "checkout":
                if checkout_visit is None:
                    raise HTTPException(status_code=404, detail="Active visit not found.")
                db.add(
                    ReaderVerificationTarget(
                        verification_id=verification.id,
                        facility_id=reader.facility_id,
                        visit_id=checkout_visit.id,
                    )
                )
            if payload.action == "checkin":
                scanned_name = payload.full_name
                scanned_document_number = payload.document_number
                if (
                    payload.reader_subject_ref is None
                    or scanned_name is None
                    or scanned_document_number is None
                ):
                    raise HTTPException(
                        status_code=422,
                        detail="The reader must provide the scanned name and fingerprint subject reference.",
                    )
                subject_hash = _reader_subject_hash(
                    reader.facility_id, payload.reader_subject_ref, settings
                )
                subject_link = db.scalar(
                    select(ReaderSubjectLink).where(
                        ReaderSubjectLink.facility_id == reader.facility_id,
                        ReaderSubjectLink.subject_lookup_hash == subject_hash,
                    ).with_for_update()
                )
                if subject_link is None:
                    subject_link = ReaderSubjectLink(
                        id=uuid.uuid4(),
                        facility_id=reader.facility_id,
                        reader_id=reader.id,
                        checkin_verification_id=verification.id,
                        subject_lookup_hash=subject_hash,
                    )
                    db.add(subject_link)
                else:
                    subject_link.reader_id = reader.id
                    subject_link.checkin_verification_id = verification.id
                db.add(
                    ReaderVerificationData(
                        verification_id=verification.id,
                        facility_id=reader.facility_id,
                        full_name_ciphertext=_encrypt_required(scanned_name, settings),
                        document_number_ciphertext=_encrypt_required(
                            scanned_document_number, settings
                        ),
                        subject_lookup_hash=subject_hash,
                    )
                )
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Reader nonce was already used.") from exc
        _audit(
            db,
            reader.facility_id,
            "reader_match_succeeded",
            reader_id=reader.id,
            details={"action": payload.action},
        )
        db.commit()
        return {
            "verification_id": str(verification.id),
            "action": verification.action,
            "expires_at": _iso(verification.expires_at),
        }

    @app.post("/api/demo/reader-verifications", status_code=201)
    def demo_reader_verification(
        payload: DemoVerificationRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        if settings.reader_mode != "mock" or settings.app_env == "production":
            raise HTTPException(status_code=404, detail="The simulated reader is disabled.")
        if payload.action == "repeat_checkin":
            if payload.reader_subject_ref is None:
                raise HTTPException(status_code=422, detail="The test reader subject reference is required.")
            return _create_repeat_fingerprint_visit(
                db,
                settings,
                auth.facility.id,
                None,
                payload.reader_subject_ref,
                new_token(),
                mode="mock",
            )
        if payload.action == "checkout":
            visit = db.scalar(
                select(Visit).where(
                    Visit.id == payload.visit_id,
                    Visit.facility_id == auth.facility.id,
                    Visit.checked_out_at.is_(None),
                )
            )
            if visit is None:
                raise HTTPException(status_code=404, detail="Active visit not found for fingerprint checkout.")
            verification = _new_visit_verification(
                db, auth.facility.id, visit, mode="mock"
            )
        else:
            if payload.document_type is None or payload.document_number is None:
                raise HTTPException(status_code=422, detail="Document type and number are required.")
            verification = _new_verification(
                db,
                settings,
                auth.facility.id,
                payload.action,
                payload.document_type,
                payload.document_number,
                mode="mock",
            )
            if (
                payload.action == "checkin"
                and payload.full_name is not None
                and payload.reader_subject_ref is not None
            ):
                db.add(
                    ReaderVerificationData(
                        verification_id=verification.id,
                        facility_id=auth.facility.id,
                        full_name_ciphertext=_encrypt_required(payload.full_name, settings),
                        document_number_ciphertext=_encrypt_required(
                            payload.document_number, settings
                        ),
                        subject_lookup_hash=_reader_subject_hash(
                            auth.facility.id, payload.reader_subject_ref, settings
                        ),
                    )
                )
        _audit(
            db,
            auth.facility.id,
            "demo_reader_match",
            actor_user_id=auth.user.id,
            details={"action": payload.action},
        )
        db.commit()
        return {
            "verification_id": str(verification.id),
            "expires_at": _iso(verification.expires_at),
            "mode": "mock",
        }

    @app.get("/api/reader/verifications/pending")
    def pending_reader_verification(
        action: Literal["checkin", "checkout", "student_exit"],
        request: Request,
        document_type: Literal["Kenyan ID", "Passport"] | None = None,
        document_number: str | None = None,
        visit_id: uuid.UUID | None = None,
        after: datetime | None = None,
        db: Session = Depends(get_db),
    ) -> Response:
        auth = _current_auth(request, db)
        _require_role(auth, "facility_admin", "operator")
        target_visit_id: uuid.UUID | None = None
        if action == "checkout":
            visit = db.scalar(
                select(Visit).where(
                    Visit.id == visit_id,
                    Visit.facility_id == auth.facility.id,
                    Visit.checked_out_at.is_(None),
                )
            )
            if visit is None:
                return Response(status_code=204)
            target_visit_id = visit.id
            resolved_type = visit.document_type
            identity_hash = visit.document_lookup_hash
        elif action == "checkin" and document_type is None and document_number is None:
            verification_query = (
                select(ReaderVerification)
                .join(
                    ReaderVerificationData,
                    ReaderVerificationData.verification_id == ReaderVerification.id,
                )
                .where(
                    ReaderVerification.facility_id == auth.facility.id,
                    ReaderVerificationData.facility_id == auth.facility.id,
                    ReaderVerification.action == "checkin",
                    ReaderVerification.matched.is_(True),
                    ReaderVerification.consumed_at.is_(None),
                    ReaderVerification.expires_at > utc_now(),
                )
            )
            if after is not None:
                verification_query = verification_query.where(
                    ReaderVerification.created_at >= _utc(after)
                )
            verification = db.scalar(
                verification_query.order_by(ReaderVerification.created_at.desc()).limit(1)
            )
            if verification is None:
                return Response(status_code=204)
            scan_data = db.get(ReaderVerificationData, verification.id)
            if scan_data is None:
                raise RuntimeError("Reader verification data was missing after the scan matched.")
            return JSONResponse(
                {
                    "verification_id": str(verification.id),
                    "expires_at": _iso(verification.expires_at),
                    "mode": verification.mode,
                    "document_type": verification.document_type,
                    "document_number": decrypt_text(
                        scan_data.document_number_ciphertext, settings
                    ),
                    "full_name": decrypt_text(scan_data.full_name_ciphertext, settings),
                }
            )
        else:
            if document_type is None or document_number is None:
                raise HTTPException(status_code=422, detail="Document type and number are required.")
            try:
                identity_hash = document_lookup_hash(
                    auth.facility.id, document_type, document_number, settings
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            resolved_type = document_type
        verification_query = select(ReaderVerification)
        if target_visit_id is not None:
            verification_query = verification_query.join(
                ReaderVerificationTarget,
                ReaderVerificationTarget.verification_id == ReaderVerification.id,
            ).where(
                ReaderVerificationTarget.visit_id == target_visit_id,
                ReaderVerificationTarget.facility_id == auth.facility.id,
            )
        verification = db.scalar(
            verification_query.where(
                ReaderVerification.facility_id == auth.facility.id,
                ReaderVerification.action == action,
                ReaderVerification.document_type == resolved_type,
                ReaderVerification.document_lookup_hash == identity_hash,
                ReaderVerification.matched.is_(True),
                ReaderVerification.consumed_at.is_(None),
                ReaderVerification.expires_at > utc_now(),
            )
            .order_by(ReaderVerification.created_at.desc())
            .limit(1)
        )
        if verification is None:
            return Response(status_code=204)
        return JSONResponse(
            {
                "verification_id": str(verification.id),
                "expires_at": _iso(verification.expires_at),
                "mode": verification.mode,
            }
        )

    @app.post("/api/checkin", status_code=201)
    def check_in(
        payload: CheckInRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin", "operator")
        if not payload.privacy_notice_acknowledged:
            raise HTTPException(status_code=422, detail="Confirm the facility privacy notice was provided.")
        try:
            identity_hash = document_lookup_hash(
                auth.facility.id, payload.document_type, payload.document_number, settings
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        verification = _consume_verification(
            db,
            settings,
            auth.facility.id,
            "checkin",
            payload.document_type,
            payload.document_number,
            payload.verification_id,
        )
        _upsert_visitor_profile(
            db,
            auth.facility.id,
            payload.document_type,
            payload.document_number,
            identity_hash,
            payload.full_name,
            payload.phone,
            verification,
            settings,
        )
        scan_data = db.get(ReaderVerificationData, verification.id)
        if scan_data is not None:
            db.delete(scan_data)
        normalized_document = "".join(
            character
            for character in payload.document_number.upper()
            if character not in " -\t\r\n"
        )
        visit = Visit(
            id=uuid.uuid4(),
            facility_id=auth.facility.id,
            full_name_ciphertext=encrypt_text(payload.full_name.strip(), settings),
            document_type=payload.document_type,
            document_lookup_hash=identity_hash,
            document_last_four=normalized_document[-4:],
            phone_ciphertext=encrypt_text(payload.phone.strip() or None, settings),
            host_ciphertext=encrypt_text(payload.host.strip(), settings),
            purpose_ciphertext=encrypt_text(payload.purpose.strip(), settings),
            checked_in_at=utc_now(),
            checkin_verification_id=verification.id,
        )
        db.add(visit)
        db.add(VisitPassDetail(visit_id=visit.id, pass_type=payload.visitor_type))
        db.add(
            VisitorDocumentSnapshot(
                visit_id=visit.id,
                document_number_ciphertext=_encrypt_required(
                    payload.document_number, settings
                ),
            )
        )
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="This visitor already has an active visit.") from exc
        _audit(
            db,
            auth.facility.id,
            "visitor_checked_in",
            actor_user_id=auth.user.id,
            reader_id=verification.reader_id,
            visit_id=visit.id,
            details={
                "verification_mode": verification.mode,
                "visitor_type": payload.visitor_type,
            },
        )
        db.commit()
        return _visit_response(
            visit,
            settings,
            payload.visitor_type,
            payload.document_number,
            reveal_document_number=True,
        )

    @app.post("/api/checkout")
    def check_out(
        payload: CheckOutRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        _require_csrf(request, auth)
        _require_role(auth, "facility_admin", "operator")
        visit = db.scalar(
            select(Visit)
            .where(
                Visit.id == payload.visit_id,
                Visit.facility_id == auth.facility.id,
                Visit.checked_out_at.is_(None),
            )
            .with_for_update()
        )
        if visit is None:
            db.rollback()
            raise HTTPException(status_code=404, detail="That visitor is not currently checked in.")
        verification = _consume_visit_verification(
            db, auth.facility.id, visit, payload.verification_id
        )
        pass_detail = db.get(VisitPassDetail, visit.id)
        visit.checked_out_at = utc_now()
        visit.checkout_verification_id = verification.id
        _audit(
            db,
            auth.facility.id,
            "visitor_checked_out",
            actor_user_id=auth.user.id,
            reader_id=verification.reader_id,
            visit_id=visit.id,
            details={"verification_mode": verification.mode},
        )
        db.commit()
        document_number = _visitor_document_number_for_visit(db, visit, settings)
        return _visit_response(
            visit,
            settings,
            pass_detail.pass_type if pass_detail is not None else "general",
            document_number,
            reveal_document_number=auth.user.role in {"facility_admin", "operator"},
        )

    @app.get("/api/visits")
    def list_visits(
        request: Request,
        view: Literal["active", "all"] = "all",
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        auth = _current_auth(request, db)
        query = select(Visit).where(Visit.facility_id == auth.facility.id)
        if view == "active":
            query = query.where(Visit.checked_out_at.is_(None))
        visits = db.scalars(
            query.order_by(Visit.checked_in_at.desc()).limit(100)
        ).all()
        pass_details = db.scalars(
            select(VisitPassDetail).where(
                VisitPassDetail.visit_id.in_([visit.id for visit in visits])
            )
        ).all()
        pass_types = {detail.visit_id: detail.pass_type for detail in pass_details}
        snapshots = db.scalars(
            select(VisitorDocumentSnapshot).where(
                VisitorDocumentSnapshot.visit_id.in_([visit.id for visit in visits])
            )
        ).all() if visits else []
        document_numbers = {
            snapshot.visit_id: decrypt_text(snapshot.document_number_ciphertext, settings)
            for snapshot in snapshots
        }
        now_local = datetime.now(EAT)
        day_start = datetime(
            now_local.year, now_local.month, now_local.day, tzinfo=EAT
        ).astimezone(timezone.utc)
        day_end = day_start + timedelta(days=1)
        active_count = db.scalar(
            select(func.count())
            .select_from(Visit)
            .where(
                Visit.facility_id == auth.facility.id,
                Visit.checked_out_at.is_(None),
            )
        )
        arrivals_today = db.scalar(
            select(func.count())
            .select_from(Visit)
            .where(
                Visit.facility_id == auth.facility.id,
                Visit.checked_in_at >= day_start,
                Visit.checked_in_at < day_end,
            )
        )
        departures_today = db.scalar(
            select(func.count())
            .select_from(Visit)
            .where(
                Visit.facility_id == auth.facility.id,
                Visit.checked_out_at >= day_start,
                Visit.checked_out_at < day_end,
            )
        )
        return {
            "visits": [
                _visit_response(
                    visit,
                    settings,
                    pass_types.get(visit.id, "general"),
                    document_numbers.get(visit.id),
                    reveal_document_number=auth.user.role in {"facility_admin", "operator"},
                )
                for visit in visits
            ],
            "stats": {
                "active": active_count or 0,
                "arrivals_today": arrivals_today or 0,
                "departures_today": departures_today or 0,
            },
        }

    @app.get("/api/audit")
    def list_audit(
        request: Request,
        db: Session = Depends(get_db),
    ) -> list[dict[str, object]]:
        auth = _current_auth(request, db)
        _require_role(auth, "facility_admin")
        entries = db.scalars(
            select(AuditLog)
            .where(AuditLog.facility_id == auth.facility.id)
            .order_by(AuditLog.created_at.desc())
            .limit(200)
        ).all()
        return [
            {
                "id": str(entry.id),
                "action": entry.action,
                "actor_user_id": str(entry.actor_user_id) if entry.actor_user_id else None,
                "reader_id": str(entry.reader_id) if entry.reader_id else None,
                "visit_id": str(entry.visit_id) if entry.visit_id else None,
                "details": entry.details,
                "created_at": _iso(entry.created_at),
            }
            for entry in entries
        ]

    return app


app = create_app()
