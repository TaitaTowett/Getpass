from __future__ import annotations

import os
import secrets
import unittest
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./gatepass_test_import.sqlite3")
os.environ.setdefault("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("IDENTIFIER_HMAC_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("SESSION_HMAC_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("READER_MODE", "mock")

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import create_database_engine, create_session_factory
from app.main import create_app
from app.models import (
    Base,
    Facility,
    FacilityProfile,
    GuardianAuthorization,
    ReaderVerification,
    Student,
    StudentMovement,
    User,
    Visit,
    VisitPassDetail,
    VisitorProfile,
)
from app.security import hash_password
from app.settings import Settings


class VisitorBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(
            database_url="sqlite://",
            data_encryption_key=Fernet.generate_key().decode(),
            identifier_hmac_key=secrets.token_urlsafe(48),
            session_hmac_key=secrets.token_urlsafe(48),
            app_env="test",
            cookie_secure=False,
            reader_mode="mock",
        )
        self.engine = create_database_engine("sqlite://")
        Base.metadata.create_all(self.engine)
        self.session_factory = create_session_factory(self.engine)
        self.app = create_app(self.settings, self.engine)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.facility_id = uuid.uuid4()
        with self.session_factory() as db:
            facility = Facility(
                id=self.facility_id,
                slug="demo-school",
                name="Demo School",
            )
            db.add(facility)
            db.add(FacilityProfile(facility_id=self.facility_id, facility_type="school"))
            db.add(
                User(
                    facility_id=self.facility_id,
                    email="admin@example.test",
                    full_name="Facility Admin",
                    role="facility_admin",
                    password_hash=hash_password("test-password-123"),
                )
            )
            db.commit()
        self.csrf = self.login()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def login(
        self,
        facility_slug: str = "demo-school",
        email: str = "admin@example.test",
        password: str = "test-password-123",
    ) -> str:
        response = self.client.post(
            "/api/auth/login",
            json={
                "facility_slug": facility_slug,
                "email": email,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["csrf_token"]

    def test_hardware_design_page_and_pdf_are_available(self) -> None:
        page = self.client.get("/hardware-design")
        pdf = self.client.get("/hardware-design.pdf")
        self.assertEqual(page.status_code, 200)
        self.assertIn("text/html", page.headers["content-type"])
        self.assertIn("150 mm", page.text)
        self.assertEqual(pdf.status_code, 200)
        self.assertIn("application/pdf", pdf.headers["content-type"])
        self.assertTrue(pdf.content.startswith(b"%PDF-"))

    def csrf_headers(self, token: str | None = None) -> dict[str, str]:
        return {"X-CSRF-Token": token or self.csrf}

    def test_production_rejects_untrusted_host_headers(self) -> None:
        production_settings = Settings(
            database_url=self.settings.database_url,
            data_encryption_key=self.settings.data_encryption_key,
            identifier_hmac_key=self.settings.identifier_hmac_key,
            session_hmac_key=self.settings.session_hmac_key,
            app_env="production",
            cookie_secure=True,
            reader_mode="device",
            trusted_hosts=("getpass.example.test",),
        )
        production_app = create_app(production_settings, self.engine)
        with TestClient(
            production_app,
            base_url="http://getpass.example.test",
        ) as client:
            trusted = client.get("/api/health/live")
            untrusted = client.get(
                "/api/health/live",
                headers={"Host": "attacker.example"},
            )
        self.assertEqual(trusted.status_code, 200)
        self.assertEqual(untrusted.status_code, 400)

    def test_production_settings_require_explicit_trusted_hosts(self) -> None:
        environment = {
            "APP_ENV": "production",
            "COOKIE_SECURE": "true",
            "READER_MODE": "device",
            "DATABASE_URL": "postgresql+psycopg://user:password@localhost/gatepass",
            "DATA_ENCRYPTION_KEY": self.settings.data_encryption_key,
            "IDENTIFIER_HMAC_KEY": self.settings.identifier_hmac_key,
            "SESSION_HMAC_KEY": self.settings.session_hmac_key,
            "TRUSTED_HOSTS": "",
        }
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "TRUSTED_HOSTS"):
                Settings.from_env()

        environment["TRUSTED_HOSTS"] = " gate.example.test, localhost "
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_env()
        self.assertEqual(
            settings.trusted_hosts,
            ("gate.example.test", "localhost"),
        )

    def create_demo_verification(
        self,
        action: str,
        document_number: str = "12-345 678",
        csrf: str | None = None,
        visit_id: str | None = None,
    ) -> str:
        payload: dict[str, object] = {"action": action}
        if action == "checkout":
            payload["visit_id"] = visit_id
        else:
            payload["document_type"] = "Kenyan ID"
            payload["document_number"] = document_number
        response = self.client.post(
            "/api/demo/reader-verifications",
            headers=self.csrf_headers(csrf),
            json=payload,
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["verification_id"]

    def checkin_payload(self, verification_id: str) -> dict[str, object]:
        return {
            "full_name": "Amina Wanjiku",
            "document_type": "Kenyan ID",
            "document_number": "12-345 678",
            "phone": "+254700000001",
            "host": "School administration",
            "purpose": "Parent meeting",
            "privacy_notice_acknowledged": True,
            "verification_id": verification_id,
        }

    def test_requires_authentication_and_csrf(self) -> None:
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/auth/session").status_code, 204)
        self.assertEqual(self.client.get("/api/visits").status_code, 401)

        self.csrf = self.login()
        verification_id = self.create_demo_verification("checkin")
        response = self.client.post(
            "/api/checkin",
            json=self.checkin_payload(verification_id),
        )
        self.assertEqual(response.status_code, 403)

    def test_checkin_checkout_encryption_and_single_use_verification(self) -> None:
        verification_id = self.create_demo_verification("checkin")
        payload = self.checkin_payload(verification_id)
        payload["visitor_type"] = "parent_guardian"
        response = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(),
            json=payload,
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["document"], "Kenyan ID ••••5678")
        self.assertEqual(response.json()["visitor_type"], "parent_guardian")

        with self.session_factory() as db:
            visit = db.scalar(select(Visit))
            visit_pass = db.scalar(select(VisitPassDetail))
            visitor_profile = db.scalar(select(VisitorProfile))
            verification = db.scalar(
                select(ReaderVerification).where(ReaderVerification.action == "checkin")
            )
            if visit is None or visit_pass is None or verification is None or visitor_profile is None:
                self.fail("Check-in, visitor profile, and reader verification should be stored.")
            self.assertNotIn("Amina Wanjiku", visit.full_name_ciphertext)
            self.assertNotIn("12345678", str(visit.document_lookup_hash))
            self.assertNotIn("12345678", visitor_profile.document_number_ciphertext)
            self.assertEqual(visit_pass.pass_type, "parent_guardian")
            self.assertIsNotNone(verification.consumed_at)

        replay = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(),
            json=self.checkin_payload(verification_id),
        )
        self.assertEqual(replay.status_code, 403)

        checkout_verification = self.create_demo_verification(
            "checkout", visit_id=response.json()["id"]
        )
        checkout = self.client.post(
            "/api/checkout",
            headers=self.csrf_headers(),
            json={
                "visit_id": response.json()["id"],
                "verification_id": checkout_verification,
            },
        )
        self.assertEqual(checkout.status_code, 200, checkout.text)
        self.assertEqual(checkout.json()["full_name"], "Amina Wanjiku")
        self.assertEqual(self.client.get("/api/visits").json()["stats"]["active"], 0)

    def test_demo_reader_supports_repeat_fingerprint_checkin(self) -> None:
        subject_ref = "mock-returning-visitor-012345"
        first_verification = self.client.post(
            "/api/demo/reader-verifications",
            headers=self.csrf_headers(),
            json={
                "action": "checkin",
                "document_type": "Kenyan ID",
                "document_number": "SAMPLE001",
                "full_name": "Demo Visitor",
                "reader_subject_ref": subject_ref,
            },
        )
        self.assertEqual(first_verification.status_code, 201, first_verification.text)
        payload = self.checkin_payload(first_verification.json()["verification_id"])
        payload.update(full_name="Demo Visitor", document_number="SAMPLE001")
        initial_checkin = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(),
            json=payload,
        )
        self.assertEqual(initial_checkin.status_code, 201, initial_checkin.text)

        checkout_verification = self.create_demo_verification(
            "checkout", visit_id=initial_checkin.json()["id"]
        )
        checkout = self.client.post(
            "/api/checkout",
            headers=self.csrf_headers(),
            json={
                "visit_id": initial_checkin.json()["id"],
                "verification_id": checkout_verification,
            },
        )
        self.assertEqual(checkout.status_code, 200, checkout.text)

        repeat_checkin = self.client.post(
            "/api/demo/reader-verifications",
            headers=self.csrf_headers(),
            json={
                "action": "repeat_checkin",
                "reader_subject_ref": subject_ref,
            },
        )
        self.assertEqual(repeat_checkin.status_code, 201, repeat_checkin.text)
        active_visits = self.client.get("/api/visits?view=active").json()["visits"]
        self.assertEqual(len(active_visits), 1)
        self.assertEqual(active_visits[0]["full_name"], "Demo Visitor")
        self.assertEqual(active_visits[0]["document_number"], "SAMPLE001")

    def test_school_arrival_and_guardian_approved_student_departure(self) -> None:
        student_response = self.client.post(
            "/api/students",
            headers=self.csrf_headers(),
            json={
                "full_name": "Njeri Sample",
                "class_name": "Grade 4",
                "admission_number": "ADM-004",
            },
        )
        self.assertEqual(student_response.status_code, 201, student_response.text)
        self.assertEqual(student_response.json()["admission_number"], "ADM-004")
        student_id = student_response.json()["id"]
        student_status = self.client.get("/api/students")
        self.assertEqual(student_status.status_code, 200, student_status.text)
        self.assertEqual(student_status.json()[0]["session_status"], "checked_out")
        duplicate_admission = self.client.post(
            "/api/students",
            headers=self.csrf_headers(),
            json={
                "full_name": "Duplicate Sample",
                "class_name": "Grade 4",
                "admission_number": "adm-004",
            },
        )
        self.assertEqual(duplicate_admission.status_code, 409)
        guardian_response = self.client.post(
            f"/api/students/{student_id}/guardians",
            headers=self.csrf_headers(),
            json={
                "full_name": "Wanjiku Sample",
                "document_type": "Kenyan ID",
                "document_number": "12345678",
                "relationship": "Parent",
            },
        )
        self.assertEqual(guardian_response.status_code, 201, guardian_response.text)
        duplicate_guardian = self.client.post(
            f"/api/students/{student_id}/guardians",
            headers=self.csrf_headers(),
            json={
                "full_name": "Wanjiku Sample",
                "document_type": "Kenyan ID",
                "document_number": "12345678",
                "relationship": "Parent",
            },
        )
        self.assertEqual(duplicate_guardian.status_code, 409)

        arrival = self.client.post(
            f"/api/students/{student_id}/arrivals",
            headers=self.csrf_headers(),
            json={
                "arrival_context": "guardian",
                "accompanied_by": "Wanjiku Sample",
                "note": "Returning after clinic",
            },
        )
        self.assertEqual(arrival.status_code, 201, arrival.text)
        self.assertEqual(arrival.json()["movement_type"], "arrival")
        self.assertEqual(arrival.json()["details"]["arrival_context"], "guardian")
        self.assertEqual(
            self.client.get("/api/students").json()[0]["session_status"],
            "in_session",
        )

        unlisted_verification = self.create_demo_verification(
            "student_exit", document_number="87654321"
        )
        unlisted_release = self.client.post(
            f"/api/students/{student_id}/departures",
            headers=self.csrf_headers(),
            json={
                "document_type": "Kenyan ID",
                "document_number": "87654321",
                "verification_id": unlisted_verification,
                "operator_approved": True,
            },
        )
        self.assertEqual(unlisted_release.status_code, 403)

        guardian_verification = self.create_demo_verification(
            "student_exit", document_number="12345678"
        )
        unapproved_release = self.client.post(
            f"/api/students/{student_id}/departures",
            headers=self.csrf_headers(),
            json={
                "document_type": "Kenyan ID",
                "document_number": "12345678",
                "verification_id": guardian_verification,
                "operator_approved": False,
            },
        )
        self.assertEqual(unapproved_release.status_code, 403)

        approved_release = self.client.post(
            f"/api/students/{student_id}/departures",
            headers=self.csrf_headers(),
            json={
                "document_type": "Kenyan ID",
                "document_number": "12345678",
                "verification_id": guardian_verification,
                "operator_approved": True,
                "note": "Collected by parent",
            },
        )
        self.assertEqual(approved_release.status_code, 201, approved_release.text)
        self.assertEqual(approved_release.json()["movement_type"], "departure")
        self.assertTrue(approved_release.json()["release_approved"])
        self.assertEqual(approved_release.json()["guardian_name"], "Wanjiku Sample")
        student_status = self.client.get("/api/students")
        self.assertEqual(student_status.status_code, 200, student_status.text)
        self.assertEqual(student_status.json()[0]["session_status"], "checked_out")
        self.assertEqual(
            len(self.client.get("/api/students/movements").json()),
            2,
        )
        revoke = self.client.delete(
            f"/api/guardians/{guardian_response.json()['id']}",
            headers=self.csrf_headers(),
        )
        self.assertEqual(revoke.status_code, 204)
        reauthorize = self.client.post(
            f"/api/students/{student_id}/guardians",
            headers=self.csrf_headers(),
            json={
                "full_name": "Wanjiku Sample",
                "document_type": "Kenyan ID",
                "document_number": "12345678",
                "relationship": "Parent",
            },
        )
        self.assertEqual(reauthorize.status_code, 201, reauthorize.text)
        self.assertEqual(reauthorize.json()["id"], guardian_response.json()["id"])
        with self.session_factory() as db:
            stored_student = db.scalar(select(Student))
            stored_guardian = db.scalar(select(GuardianAuthorization))
            departures = db.scalars(
                select(StudentMovement).where(StudentMovement.movement_type == "departure")
            ).all()
            verification = db.scalar(
                select(ReaderVerification).where(
                    ReaderVerification.id == uuid.UUID(guardian_verification)
                )
            )
            if stored_student is None or stored_guardian is None or verification is None:
                self.fail("Student roster and departure verification should be stored.")
            self.assertNotIn("Njeri Sample", stored_student.full_name_ciphertext)
            self.assertNotIn("Wanjiku Sample", stored_guardian.full_name_ciphertext)
            self.assertNotIn("12345678", stored_guardian.document_lookup_hash)
            self.assertEqual(len(departures), 1)
            self.assertTrue(departures[0].release_approved)
            self.assertIsNotNone(verification.consumed_at)

    def test_facilities_cannot_read_each_others_visits(self) -> None:
        verification_id = self.create_demo_verification("checkin")
        response = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(),
            json=self.checkin_payload(verification_id),
        )
        self.assertEqual(response.status_code, 201)
        visit_id = response.json()["id"]
        student = self.client.post(
            "/api/students",
            headers=self.csrf_headers(),
            json={
                "full_name": "Private Student",
                "class_name": "Grade 3",
                "admission_number": "PRIVATE-003",
            },
        )
        self.assertEqual(student.status_code, 201, student.text)

        other_facility_id = uuid.uuid4()
        with self.session_factory() as db:
            db.add(Facility(id=other_facility_id, slug="other-site", name="Other Site"))
            db.add(FacilityProfile(facility_id=other_facility_id, facility_type="school"))
            db.add(
                User(
                    facility_id=other_facility_id,
                    email="admin@example.test",
                    full_name="Other Admin",
                    role="facility_admin",
                    password_hash=hash_password("test-password-123"),
                )
            )
            db.commit()
        other_csrf = self.login("other-site")

        response = self.client.get("/api/visits")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stats"]["active"], 0)
        self.assertEqual(self.client.get("/api/students").json(), [])
        foreign_arrival = self.client.post(
            f"/api/students/{student.json()['id']}/arrivals",
            headers=self.csrf_headers(other_csrf),
            json={"arrival_context": "staff"},
        )
        self.assertEqual(foreign_arrival.status_code, 404)
        checkout = self.client.post(
            "/api/checkout",
            headers=self.csrf_headers(other_csrf),
            json={
                "visit_id": visit_id,
                "verification_id": str(uuid.uuid4()),
            },
        )
        self.assertEqual(checkout.status_code, 404)

    def test_reader_nonce_is_one_time_and_reader_is_facility_scoped(self) -> None:
        create = self.client.post(
            "/api/readers",
            headers=self.csrf_headers(),
            json={"label": "Front desk reader"},
        )
        self.assertEqual(create.status_code, 201, create.text)
        reader_token = create.json()["reader_token"]
        payload = {
            "action": "checkin",
            "document_type": "Kenyan ID",
            "document_number": "12345678",
            "full_name": "Nonce Test Visitor",
            "reader_subject_ref": secrets.token_urlsafe(24),
            "matched": True,
            "nonce": secrets.token_urlsafe(24),
        }
        headers = {"X-Reader-Token": reader_token}
        first = self.client.post("/api/reader/verifications", headers=headers, json=payload)
        self.assertEqual(first.status_code, 201, first.text)
        replay = self.client.post("/api/reader/verifications", headers=headers, json=payload)
        self.assertEqual(replay.status_code, 409)
        student_exit_payload = {
            "action": "student_exit",
            "document_type": "Kenyan ID",
            "document_number": "12345678",
            "nonce": secrets.token_urlsafe(24),
            "matched": True,
        }
        student_exit = self.client.post(
            "/api/reader/verifications",
            headers=headers,
            json=student_exit_payload,
        )
        self.assertEqual(student_exit.status_code, 201, student_exit.text)

    def test_device_reader_supports_embedded_checkin_and_fingerprint_only_checkout(self) -> None:
        reader_response = self.client.post(
            "/api/readers",
            headers=self.csrf_headers(),
            json={"label": "Combined entry reader"},
        )
        self.assertEqual(reader_response.status_code, 201, reader_response.text)
        reader_token = reader_response.json()["reader_token"]
        reader_headers = {"X-Reader-Token": reader_token}
        subject_ref = secrets.token_urlsafe(24)
        checkin_verification = self.client.post(
            "/api/reader/verifications",
            headers=reader_headers,
            json={
                "action": "checkin",
                "document_type": "Kenyan ID",
                "document_number": "55667788",
                "full_name": "Device Test Visitor",
                "reader_subject_ref": subject_ref,
                "matched": True,
                "nonce": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(checkin_verification.status_code, 201, checkin_verification.text)
        pending_scan = self.client.get(
            "/api/reader/verifications/pending",
            params={"action": "checkin"},
        )
        self.assertEqual(pending_scan.status_code, 200, pending_scan.text)
        self.assertEqual(pending_scan.json()["full_name"], "Device Test Visitor")
        self.assertEqual(pending_scan.json()["document_number"], "55667788")
        checkin = self.checkin_payload(checkin_verification.json()["verification_id"])
        checkin["document_number"] = pending_scan.json()["document_number"]
        checkin["full_name"] = pending_scan.json()["full_name"]
        response = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(),
            json=checkin,
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["document_number"], "55667788")
        visit_id = response.json()["id"]

        checkout_verification = self.client.post(
            "/api/reader/verifications",
            headers=reader_headers,
            json={
                "action": "checkout",
                "reader_subject_ref": subject_ref,
                "matched": True,
                "nonce": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(checkout_verification.status_code, 201, checkout_verification.text)
        pending = self.client.get(
            "/api/reader/verifications/pending",
            params={"action": "checkout", "visit_id": visit_id},
        )
        self.assertEqual(pending.status_code, 200, pending.text)
        checkout = self.client.post(
            "/api/checkout",
            headers=self.csrf_headers(),
            json={
                "visit_id": visit_id,
                "verification_id": checkout_verification.json()["verification_id"],
            },
        )
        self.assertEqual(checkout.status_code, 200, checkout.text)
        self.assertEqual(checkout.json()["full_name"], "Device Test Visitor")

        repeat_checkin = self.client.post(
            "/api/reader/verifications",
            headers=reader_headers,
            json={
                "action": "repeat_checkin",
                "reader_subject_ref": subject_ref,
                "matched": True,
                "nonce": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(repeat_checkin.status_code, 201, repeat_checkin.text)
        active_visits = self.client.get("/api/visits?view=active").json()["visits"]
        self.assertEqual(len(active_visits), 1)
        self.assertEqual(active_visits[0]["full_name"], "Device Test Visitor")
        self.assertEqual(active_visits[0]["document_number"], "55667788")
        duplicate_repeat = self.client.post(
            "/api/reader/verifications",
            headers=reader_headers,
            json={
                "action": "repeat_checkin",
                "reader_subject_ref": subject_ref,
                "matched": True,
                "nonce": secrets.token_urlsafe(24),
            },
        )
        self.assertEqual(duplicate_repeat.status_code, 409)

    def test_school_workflows_are_configurable_per_facility(self) -> None:
        public_facility_id = uuid.uuid4()
        with self.session_factory() as db:
            db.add(
                Facility(
                    id=public_facility_id,
                    slug="public-site",
                    name="Public Site",
                )
            )
            db.add(
                User(
                    facility_id=public_facility_id,
                    email="admin@example.test",
                    full_name="Public Site Admin",
                    role="facility_admin",
                    password_hash=hash_password("test-password-123"),
                )
            )
            db.commit()
        public_csrf = self.login("public-site")
        self.assertEqual(self.client.get("/api/students").status_code, 404)
        update = self.client.put(
            "/api/facility/profile",
            headers=self.csrf_headers(public_csrf),
            json={"facility_type": "private_school"},
        )
        self.assertEqual(update.status_code, 200, update.text)
        self.assertEqual(update.json()["facility_type"], "private_school")
        self.assertEqual(self.client.get("/api/students").status_code, 200)

    def test_viewer_cannot_check_in_or_manage_staff(self) -> None:
        student = self.client.post(
            "/api/students",
            headers=self.csrf_headers(),
            json={
                "full_name": "Viewer Test Student",
                "class_name": "Grade 2",
                "admission_number": "VIEWER-002",
            },
        )
        self.assertEqual(student.status_code, 201, student.text)
        with self.session_factory() as db:
            db.add(
                User(
                    facility_id=self.facility_id,
                    email="viewer@example.test",
                    full_name="Read Only",
                    role="viewer",
                    password_hash=hash_password("viewer-password-123"),
                )
            )
            db.commit()
        viewer_csrf = self.login(
            email="viewer@example.test", password="viewer-password-123"
        )
        staff_response = self.client.post(
            "/api/staff",
            headers=self.csrf_headers(viewer_csrf),
            json={
                "email": "new@example.test",
                "full_name": "New User",
                "password": "new-user-password-123",
                "role": "operator",
            },
        )
        self.assertEqual(staff_response.status_code, 403)
        student_create = self.client.post(
            "/api/students",
            headers=self.csrf_headers(viewer_csrf),
            json={
                "full_name": "Not Allowed",
                "class_name": "Grade 1",
                "admission_number": "NOT-ALLOWED-1",
            },
        )
        self.assertEqual(student_create.status_code, 403)
        arrival = self.client.post(
            f"/api/students/{student.json()['id']}/arrivals",
            headers=self.csrf_headers(viewer_csrf),
            json={"arrival_context": "staff"},
        )
        self.assertEqual(arrival.status_code, 403)
        verification_id = self.create_demo_verification(
            "checkin", csrf=viewer_csrf
        )
        checkin = self.client.post(
            "/api/checkin",
            headers=self.csrf_headers(viewer_csrf),
            json=self.checkin_payload(verification_id),
        )
        self.assertEqual(checkin.status_code, 403)

    def test_account_lockout_follows_repeated_failed_signins(self) -> None:
        for _ in range(5):
            response = self.client.post(
                "/api/auth/login",
                json={
                    "facility_slug": "demo-school",
                    "email": "admin@example.test",
                    "password": "incorrect-password",
                },
            )
            self.assertEqual(response.status_code, 401)

        locked_response = self.client.post(
            "/api/auth/login",
            json={
                "facility_slug": "demo-school",
                "email": "admin@example.test",
                "password": "test-password-123",
            },
        )
        self.assertEqual(locked_response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
