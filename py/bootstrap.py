from __future__ import annotations

import argparse
import re
from getpass import getpass

from dotenv import load_dotenv
from sqlalchemy import select

from app.database import create_database_engine, create_session_factory
from app.models import Base, Facility, FacilityProfile, User
from app.security import hash_password
from app.settings import Settings


def main() -> None:
    load_dotenv()
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description="Create the first facility administrator.")
    parser.add_argument("--slug", required=True, help="Unique facility slug, e.g. demo-school")
    parser.add_argument("--name", required=True, help="Facility name")
    parser.add_argument("--admin-email", required=True, help="Administrator email address")
    parser.add_argument("--admin-name", default="Facility Administrator")
    parser.add_argument(
        "--facility-type",
        choices=(
            "public_ministry",
            "public_hospital",
            "public_school",
            "private_school",
            "private_hospital",
        ),
        default="public_ministry",
        help="Select the facility's ownership and institution type",
    )
    args = parser.parse_args()

    slug = args.slug.strip().lower()
    email = args.admin_email.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", slug):
        parser.error("slug must contain 2–64 lowercase letters, digits, or hyphens.")
    if "@" not in email or len(email) > 254:
        parser.error("admin-email must be a valid email address.")
    password = getpass("Administrator password (12+ characters): ")
    confirmation = getpass("Confirm password: ")
    if len(password) < 12:
        parser.error("Administrator password must be at least 12 characters.")
    if password != confirmation:
        parser.error("Passwords do not match.")

    engine = create_database_engine(settings.database_url)
    Base.metadata.create_all(bind=engine)
    session_factory = create_session_factory(engine)
    with session_factory() as db:
        existing = db.scalar(select(Facility).where(Facility.slug == slug))
        if existing is not None:
            parser.error("That facility slug already exists.")
        facility = Facility(slug=slug, name=args.name.strip())
        db.add(facility)
        db.flush()
        db.add(
            FacilityProfile(
                facility_id=facility.id,
                facility_type=args.facility_type,
            )
        )
        db.add(
            User(
                facility_id=facility.id,
                email=email,
                full_name=args.admin_name.strip(),
                role="facility_admin",
                password_hash=hash_password(password),
            )
        )
        db.commit()
    engine.dispose()
    print(f"Created administrator for facility '{slug}'.")


if __name__ == "__main__":
    main()
