import json
from typing import List, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from .models import Policy, Scan, Finding
from .schemas import PolicyCreate, ScanTextRequest, FindingOut, PolicyOut
from .storage import SessionLocal
from .detectors import run_detectors, filter_by_min_severity, NAME_TO_DETECTOR

class PolicyService:
    def create_or_update_policy(self, payload: PolicyCreate) -> PolicyOut:
        with SessionLocal() as db:
            policy: Optional[Policy] = db.query(Policy).filter(Policy.name == payload.name).first()
            if policy is None:
                policy = Policy(name=payload.name)
                db.add(policy)
            policy.enabled = payload.enabled
            policy.detectors = json.dumps(payload.detectors)
            policy.min_severity = payload.min_severity
            policy.actions = json.dumps(payload.actions)
            db.commit()
            db.refresh(policy)
            return PolicyOut(
                id=policy.id,
                name=policy.name,
                enabled=policy.enabled,
                detectors=json.loads(policy.detectors or "[]"),
                min_severity=policy.min_severity,
                actions=json.loads(policy.actions or "[]"),
            )

    def list_policies(self) -> List[PolicyOut]:
        with SessionLocal() as db:
            policies = db.query(Policy).all()
            out: List[PolicyOut] = []
            for p in policies:
                out.append(
                    PolicyOut(
                        id=p.id,
                        name=p.name,
                        enabled=p.enabled,
                        detectors=json.loads(p.detectors or "[]"),
                        min_severity=p.min_severity,
                        actions=json.loads(p.actions or "[]"),
                    )
                )
            return out

class ScanService:
    def _resolve_policy(self, db: Session, policy_name: Optional[str]) -> Policy:
        if policy_name:
            policy = db.query(Policy).filter(Policy.name == policy_name).first()
        else:
            policy = db.query(Policy).filter(Policy.enabled == True).order_by(Policy.id.asc()).first()
        if not policy:
            raise HTTPException(status_code=400, detail="Policy not found")
        return policy

    def scan_text(self, payload: ScanTextRequest) -> List[FindingOut]:
        with SessionLocal() as db:
            policy = self._resolve_policy(db, payload.policy_name)
            detector_names = json.loads(policy.detectors or "[]")
            findings_data = run_detectors(payload.text, detector_names)
            findings_data = filter_by_min_severity(findings_data, policy.min_severity)

            scan = Scan(policy_name=policy.name, source_kind="text")
            db.add(scan)
            db.flush()

            findings_out: List[FindingOut] = []
            for f in findings_data:
                finding = Finding(
                    scan_id=scan.id,
                    detector=f["detector"],
                    match=f["match"],
                    start=f["start"],
                    end=f["end"],
                    severity=f["severity"],
                )
                db.add(finding)
                db.flush()
                findings_out.append(
                    FindingOut(
                        id=finding.id,
                        detector=finding.detector,
                        match=finding.match,
                        start=finding.start,
                        end=finding.end,
                        severity=finding.severity,
                    )
                )
            db.commit()
            return findings_out

    def scan_bytes(self, data: bytes, policy_name: Optional[str]) -> List[FindingOut]:
        # MVP: treat as utf-8 text, ignore decoding errors
        text = data.decode("utf-8", errors="ignore")
        return self.scan_text(ScanTextRequest(text=text, policy_name=policy_name))

    def list_recent_findings(self, limit: int = 100) -> List[FindingOut]:
        with SessionLocal() as db:
            q = db.query(Finding).order_by(Finding.id.desc()).limit(limit).all()
            return [
                FindingOut(
                    id=f.id,
                    detector=f.detector,
                    match=f.match,
                    start=f.start,
                    end=f.end,
                    severity=f.severity,
                )
                for f in q
            ]

policy_service = PolicyService()
scan_service = ScanService()