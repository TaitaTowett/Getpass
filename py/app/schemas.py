from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(APIModel):
    facility_slug: str = Field(min_length=2, max_length=64)
    facility_type: Literal[
        "public_ministry",
        "public_hospital",
        "public_school",
        "private_school",
        "private_hospital",
    ] | None = None
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("facility_slug", "email")
    @classmethod
    def normalize_login_values(cls, value: str) -> str:
        return value.strip().lower()


class CheckInRequest(APIModel):
    full_name: str = Field(min_length=1, max_length=100)
    visitor_type: Literal[
        "general", "parent_guardian", "event_guest", "contractor", "delivery"
    ] = "general"
    document_type: Literal["Kenyan ID", "Passport"]
    document_number: str = Field(min_length=2, max_length=32)
    phone: str = Field(default="", max_length=24)
    host: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=1, max_length=200)
    privacy_notice_acknowledged: bool
    verification_id: UUID

    @field_validator("full_name", "host", "purpose")
    @classmethod
    def require_nonblank_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("This field must not be blank.")
        return normalized

    @field_validator("document_number")
    @classmethod
    def trim_document_number(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("ID or passport number is required.")
        return normalized

    @field_validator("phone")
    @classmethod
    def trim_phone(cls, value: str) -> str:
        return value.strip()


class CheckOutRequest(APIModel):
    visit_id: UUID
    verification_id: UUID


class DemoVerificationRequest(APIModel):
    action: Literal["checkin", "checkout", "student_exit", "repeat_checkin"]
    document_type: Literal["Kenyan ID", "Passport"] | None = None
    document_number: str | None = Field(default=None, min_length=2, max_length=32)
    visit_id: UUID | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=100)
    reader_subject_ref: str | None = Field(default=None, min_length=16, max_length=128)

    @model_validator(mode="after")
    def require_action_identity(self) -> DemoVerificationRequest:
        if self.action == "repeat_checkin":
            if self.reader_subject_ref is None:
                raise ValueError("A reader subject reference is required for repeat check-in.")
            if any((self.document_type, self.document_number, self.visit_id, self.full_name)):
                raise ValueError("Repeat check-in must use fingerprint identification only.")
        elif self.action == "checkout":
            if self.visit_id is None:
                raise ValueError("A visit must be selected for fingerprint checkout.")
        elif self.document_type is None or self.document_number is None:
            raise ValueError("Document type and number are required for this reader action.")
        return self


class ReaderVerificationRequest(APIModel):
    action: Literal["checkin", "checkout", "student_exit", "repeat_checkin"]
    document_type: Literal["Kenyan ID", "Passport"] | None = None
    document_number: str | None = Field(default=None, min_length=2, max_length=32)
    visit_id: UUID | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=100)
    reader_subject_ref: str | None = Field(default=None, min_length=16, max_length=128)
    matched: bool
    nonce: str = Field(min_length=16, max_length=128)

    @field_validator("document_number")
    @classmethod
    def trim_document_number(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

    @model_validator(mode="after")
    def require_action_identity(self) -> ReaderVerificationRequest:
        if self.action == "repeat_checkin":
            if self.reader_subject_ref is None:
                raise ValueError("A reader subject reference is required for repeat check-in.")
            if any((self.document_type, self.document_number, self.visit_id, self.full_name)):
                raise ValueError("Repeat check-in must use fingerprint identification only.")
        elif self.action == "checkout":
            if self.visit_id is None and self.reader_subject_ref is None:
                raise ValueError("A matched visit or reader subject is required for fingerprint checkout.")
            if self.visit_id is not None and self.reader_subject_ref is not None:
                raise ValueError("Use either the reader subject or visit ID for checkout, not both.")
        elif self.document_type is None or self.document_number is None:
            raise ValueError("Document type and number are required for this reader action.")
        elif self.action == "checkin":
            if self.reader_subject_ref is None or self.full_name is None:
                raise ValueError(
                    "A reader subject reference and the name read from the ID are required for check-in."
                )
        return self

    @field_validator("full_name")
    @classmethod
    def trim_scanned_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("The name read from the ID must not be blank.")
        return normalized


class StaffCreateRequest(APIModel):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: Literal["facility_admin", "operator", "viewer"]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized

    @field_validator("full_name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Name must not be blank.")
        return normalized


class ReaderCreateRequest(APIModel):
    label: str = Field(min_length=1, max_length=100)

    @field_validator("label")
    @classmethod
    def trim_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Reader label must not be blank.")
        return normalized


class FacilityProfileRequest(APIModel):
    facility_type: Literal[
        "public_ministry",
        "public_hospital",
        "public_school",
        "private_school",
        "private_hospital",
    ]


class StudentCreateRequest(APIModel):
    full_name: str = Field(min_length=1, max_length=100)
    class_name: str = Field(min_length=1, max_length=40)
    admission_number: str = Field(min_length=1, max_length=32)

    @field_validator("full_name", "class_name")
    @classmethod
    def require_nonblank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("This field must not be blank.")
        return normalized

    @field_validator("admission_number")
    @classmethod
    def trim_admission_number(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Admission or registration number must not be blank.")
        return normalized


class GuardianCreateRequest(APIModel):
    full_name: str = Field(min_length=1, max_length=100)
    document_type: Literal["Kenyan ID", "Passport"]
    document_number: str = Field(min_length=2, max_length=32)
    relationship: str = Field(min_length=1, max_length=40)

    @field_validator("full_name", "relationship")
    @classmethod
    def require_nonblank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("This field must not be blank.")
        return normalized

    @field_validator("document_number")
    @classmethod
    def trim_document_number(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("ID or passport number is required.")
        return normalized


class StudentArrivalRequest(APIModel):
    arrival_context: Literal["guardian", "school_bus", "staff", "other"] = "other"
    accompanied_by: str = Field(default="", max_length=100)
    note: str = Field(default="", max_length=200)

    @field_validator("accompanied_by", "note")
    @classmethod
    def trim_optional_text(cls, value: str) -> str:
        return value.strip()


class StudentDepartureRequest(APIModel):
    document_type: Literal["Kenyan ID", "Passport"]
    document_number: str = Field(min_length=2, max_length=32)
    verification_id: UUID
    operator_approved: bool
    note: str = Field(default="", max_length=200)

    @field_validator("document_number")
    @classmethod
    def trim_document_number(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Guardian ID or passport number is required.")
        return normalized

    @field_validator("note")
    @classmethod
    def trim_note(cls, value: str) -> str:
        return value.strip()
