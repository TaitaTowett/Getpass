from __future__ import annotations

import argparse

from dotenv import load_dotenv
from sqlalchemy import select

from app.database import create_database_engine, create_session_factory
from app.models import Base, Facility, FacilityProfile, GuardianAuthorization, Student, User
from app.security import (
    admission_number_lookup_hash,
    document_lookup_hash,
    encrypt_text,
    hash_password,
)
from app.settings import Settings


DEMO_FACILITIES = (
    {
        "slug": "demo-public",
        "name": "GETPASS Demo Ministry",
        "facility_type": "public_ministry",
        "email": "gate@demo-public.test",
    },
    {
        "slug": "demo-school",
        "name": "GETPASS Demo School",
        "facility_type": "public_school",
        "email": "gate@demo-school.test",
    },
)


def main() -> None:
    load_dotenv()
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description="Create fictional local GETPASS demo accounts.")
    parser.add_argument("--password", required=True, help="Password to set for both demo operators")
    args = parser.parse_args()
    if settings.app_env != "development" or settings.reader_mode != "mock":
        parser.error("Demo data can only be created in development with the mock reader enabled.")
    if len(args.password) < 12:
        parser.error("Demo password must be at least 12 characters.")

    engine = create_database_engine(settings.database_url)
    Base.metadata.create_all(bind=engine)
    session_factory = create_session_factory(engine)
    with session_factory() as db:
        existing = db.scalars(
            select(Facility).where(
                Facility.slug.in_([facility["slug"] for facility in DEMO_FACILITIES])
            )
        ).all()
        if existing:
            parser.error("A demo facility already exists; refusing to overwrite its records.")

        for facility_info in DEMO_FACILITIES:
            facility = Facility(
                slug=facility_info["slug"],
                name=facility_info["name"],
            )
            db.add(facility)
            db.flush()
            db.add(
                FacilityProfile(
                    facility_id=facility.id,
                    facility_type=facility_info["facility_type"],
                )
            )
            db.add(
                User(
                    facility_id=facility.id,
                    email=facility_info["email"],
                    full_name="Demo Gate Operator",
                    role="facility_admin",
                    password_hash=hash_password(args.password),
                )
            )
            if facility_info["facility_type"] == "public_school":
                admission_number = "DEMO-2026-001"
                student = Student(
                    facility_id=facility.id,
                    full_name_ciphertext=encrypt_text("Demo Learner", settings),
                    class_ciphertext=encrypt_text("Grade 5", settings),
                    admission_number_ciphertext=encrypt_text(admission_number, settings),
                    admission_number_lookup_hash=admission_number_lookup_hash(
                        facility.id, admission_number, settings
                    ),
                )
                db.add(student)
                db.flush()
                guardian_document = "DEMO8765"
                db.add(
                    GuardianAuthorization(
                        facility_id=facility.id,
                        student_id=student.id,
                        full_name_ciphertext=encrypt_text("Demo Guardian", settings),
                        document_type="Kenyan ID",
                        document_lookup_hash=document_lookup_hash(
                            facility.id, "Kenyan ID", guardian_document, settings
                        ),
                        document_last_four=guardian_document[-4:],
                        relationship_ciphertext=encrypt_text("Parent", settings),
                    )
                )
        db.commit()
    engine.dispose()
    print("Created fictional public-facility and school demo accounts.")
    for facility in DEMO_FACILITIES:
        print(f"{facility['slug']} · {facility['email']}")
    print("Use the supplied demo password for both accounts.")


if __name__ == "__main__":
    main()
