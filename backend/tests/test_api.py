import pytest
import datetime
import uuid
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.db.session import engine, Base, AsyncSessionLocal
from backend.app.engines.readiness_engine import readiness_engine

@pytest.fixture(autouse=True)
async def init_test_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        await readiness_engine.initialize_sources_if_empty(session)
    yield

@pytest.mark.asyncio
async def test_api_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"

@pytest.mark.asyncio
async def test_api_readiness_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/v1/readiness")
        assert res.status_code == 200
        data = res.json()
        assert "score" in data
        assert "sources" in data
        assert len(data["sources"]) > 0

@pytest.mark.asyncio
async def test_api_telemetry_ingest_and_alert_flow():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        now = datetime.datetime.now(datetime.timezone.utc)
        batch_uid = uuid.uuid4().hex[:6]
        payload = {
            "collector_id": "test-agent-ubuntu",
            "events": [
                {
                    "event_id": f"EVT-API-{batch_uid}-{i}",
                    "host": "ubuntu-lab",
                    "timestamp": (now + datetime.timedelta(seconds=i*3)).isoformat(),
                    "source": "auth.log",
                    "event_type": "ssh_auth_failure",
                    "user": "root",
                    "source_ip": "192.168.56.200",
                    "message": f"Failed password for root from 192.168.56.200 port 5000{i} ssh2",
                    "raw_log": f"Feb 26 12:00:0{i} ubuntu-lab sshd[90{i}]: Failed password for root from 192.168.56.200 port 5000{i}"
                }
                for i in range(4)
            ]
        }
        res = await ac.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers={"x-collector-key": settings.SECRET_COLLECTOR_KEY}
        )
        assert res.status_code == 200
        resp_data = res.json()
        assert resp_data["ingested_count"] >= 3
        assert resp_data["alerts_triggered"] >= 1

        # Check alerts endpoint
        alerts_res = await ac.get("/api/v1/detection/alerts")
        assert alerts_res.status_code == 200
        alerts = alerts_res.json()
        assert len(alerts) > 0
        assert any(a["rule_id"] in ["RULE-SSH-BRUTEFORCE", "RULE-ROOT-AUTH-ATTEMPT"] for a in alerts)

        # Check investigation case endpoint
        cases_res = await ac.get("/api/v1/investigation/cases")
        assert cases_res.status_code == 200
        cases = cases_res.json()
        assert len(cases) > 0
        case_id = cases[0]["case_id"]

        # Check PDF report generation endpoint
        pdf_res = await ac.get(f"/api/v1/investigation/case/{case_id}/report.pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF")

@pytest.mark.asyncio
async def test_api_prioritization():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        prio_payload = {
            "strategy": "adaptive",
            "budget": 60.0,
            "threat_context": "T1110"
        }
        prio_res = await ac.post("/api/v1/prioritization/run", json=prio_payload)
        assert prio_res.status_code == 200
        pdata = prio_res.json()
        assert pdata["strategy"] == "adaptive"
        assert pdata["budget_used"] <= 60.0

        # Test compare endpoint
        comp_res = await ac.get("/api/v1/prioritization/compare?budget=50&threat_context=T1110")
        assert comp_res.status_code == 200
        comp_data = comp_res.json()
        assert len(comp_data["strategies_comparison"]) == 5

@pytest.mark.asyncio
async def test_api_vault_acquire_prioritized_selection():
    """Vault preserves only sources backed by real collector telemetry and reports the rest."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        now = datetime.datetime.now(datetime.timezone.utc)
        uid = uuid.uuid4().hex[:6]
        events = [
            {
                "event_id": f"EVT-SEL-{uid}-{i}",
                "host": "ubuntu-lab",
                "timestamp": (now + datetime.timedelta(seconds=i)).isoformat(),
                "source": "auth.log",
                "event_type": "ssh_auth_failure",
                "user": "testuser",
                "source_ip": "192.168.56.201",
                "message": f"Failed password for testuser from 192.168.56.201 port 6000{i} ssh2",
                "raw_log": f"sshd[70{i}]: Failed password for testuser from 192.168.56.201 port 6000{i} ssh2"
            }
            for i in range(4)
        ]
        res = await ac.post(
            "/api/v1/telemetry/ingest",
            json={"collector_id": "test-agent", "events": events},
            headers={"X-Collector-Key": settings.SECRET_COLLECTOR_KEY}
        )
        assert res.status_code == 200

        cases = (await ac.get("/api/v1/investigation/cases")).json()
        case = next(c for c in cases if c["primary_technique"] == "T1110")

        # 1. Client-provided selection (what the Prioritization page shows as selected)
        res = await ac.post("/api/v1/vault/acquire-selection", json={
            "case_id": case["case_id"],
            "source_keys": ["user_session", "ssh_auth", "network_conn", "file_mod"]
        })
        assert res.status_code == 200
        data = res.json()
        assert data["selection"]["origin"] == "client_selection"
        assert [a["source_key"] for a in data["acquired"]] == ["ssh_auth"]
        assert data["acquired"][0]["record_count"] >= 4
        reasons = {s["source_key"]: s["reason"] for s in data["skipped"]}
        assert "host-side acquisition" in reasons["user_session"]
        assert "host-side acquisition" in reasons["network_conn"]
        assert "nothing to preserve" in reasons["file_mod"]

        # 2. Server-side adaptive selection (what the Vault button uses)
        res = await ac.post("/api/v1/vault/acquire-selection", json={"case_id": case["case_id"], "budget": 60})
        assert res.status_code == 200
        data = res.json()
        assert data["selection"]["origin"] == "server_adaptive"
        assert data["selection"]["run_id"]
        assert data["selection"]["threat_context"] == "T1110"
        assert "ssh_auth" in data["selection"]["source_keys"]

        # 3. Unknown case
        res = await ac.post("/api/v1/vault/acquire-selection", json={"case_id": "CASE-NOPE", "source_keys": ["ssh_auth"]})
        assert res.status_code == 404


def _auth_events(uid, host, ip, user, n, event_type="ssh_auth_failure", start=0):
    now = datetime.datetime.now(datetime.timezone.utc)
    verb = "Accepted password" if event_type == "ssh_auth_success" else "Failed password"
    return [
        {
            "event_id": f"EVT-{event_type[-7:]}-{uid}-{user}-{start + i}",
            "host": host,
            "timestamp": (now + datetime.timedelta(seconds=start + i)).isoformat(),
            "source": "auth.log",
            "event_type": event_type,
            "user": user,
            "source_ip": ip,
            "message": f"{verb} for {user} from {ip} port {50000 + start + i} ssh2",
            "raw_log": f"sshd[{uid}-{start + i}]: {verb} for {user} from {ip} port {50000 + start + i} ssh2"
        }
        for i in range(n)
    ]


async def _ingest(ac, events):
    res = await ac.post(
        "/api/v1/telemetry/ingest",
        json={"collector_id": "test-agent", "events": events},
        headers={"X-Collector-Key": settings.SECRET_COLLECTOR_KEY}
    )
    assert res.status_code == 200, res.text


async def _cases_for_host(ac, host):
    cases = (await ac.get("/api/v1/investigation/cases")).json()
    return [c for c in cases if host in c["title"]]


@pytest.mark.asyncio
async def test_case_one_attack_one_case_with_computed_findings():
    """Brute force + root attempts from the same attacker/host form ONE case,
    and findings are computed from data (no unchecked 'not breached' claim)."""
    uid = uuid.uuid4().hex[:6]
    host, ip = f"lab-{uid}", f"10.9.{int(uid[:2], 16)}.{int(uid[2:4], 16)}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await _ingest(ac, _auth_events(uid, host, ip, "testuser", 5))
        await _ingest(ac, _auth_events(uid, host, ip, "root", 2, start=10))

        cases = await _cases_for_host(ac, host)
        assert len(cases) == 1, [c["title"] for c in cases]
        case = cases[0]
        assert case["primary_technique"] == "T1110"
        assert len(case["supporting_alert_ids"]) >= 2  # brute-force + root-login alerts
        assert case["analyst_notes"] == ""              # system no longer writes as the analyst
        assert any("No successful SSH login" in f for f in case["findings"])
        assert not any("not observed to be successfully breached" in f for f in case["findings"])
        assert "7 supporting events" in case["summary"]  # summary reflects current data


@pytest.mark.asyncio
async def test_case_detects_successful_login_as_possible_compromise():
    uid = uuid.uuid4().hex[:6]
    host, ip = f"lab-{uid}", f"10.8.{int(uid[:2], 16)}.{int(uid[2:4], 16)}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await _ingest(ac, _auth_events(uid, host, ip, "testuser", 4))
        readiness_at_open = (await _cases_for_host(ac, host))[0]["readiness_score_at_time"]

        await _ingest(ac, _auth_events(uid, host, ip, "testuser", 1, event_type="ssh_auth_success", start=20))

        case = (await _cases_for_host(ac, host))[0]
        assert case["severity"] == "CRITICAL"
        assert case["title"].startswith("Possible compromise")
        assert any(f.startswith("SUCCESSFUL SSH login for 'testuser'") for f in case["findings"])
        assert case["unresolved_questions"][0].startswith("What did the attacker do after logging in")
        assert case["readiness_score_at_time"] == readiness_at_open  # recorded once, at open


@pytest.mark.asyncio
async def test_case_status_change_keeps_notes_and_closes_alerts():
    uid = uuid.uuid4().hex[:6]
    host, ip = f"lab-{uid}", f"10.7.{int(uid[:2], 16)}.{int(uid[2:4], 16)}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await _ingest(ac, _auth_events(uid, host, ip, "testuser", 4))
        case = (await _cases_for_host(ac, host))[0]
        cid = case["case_id"]

        res = await ac.put(f"/api/v1/investigation/case/{cid}", json={"analyst_notes": "Blocked IP at firewall."})
        assert res.status_code == 200
        res = await ac.put(f"/api/v1/investigation/case/{cid}", json={"status": "CLOSED"})
        assert res.status_code == 200
        assert res.json()["analyst_notes"] == "Blocked IP at firewall."  # status-only update keeps notes

        alerts = (await ac.get("/api/v1/detection/alerts")).json()
        case_alerts = [a for a in alerts if a["alert_id"] in case["supporting_alert_ids"]]
        assert case_alerts and all(a["status"] == "CLOSED" for a in case_alerts)

        # A new burst after closing opens a new case instead of reviving the closed one.
        await _ingest(ac, _auth_events(uid, host, ip, "testuser", 4, start=30))
        cases = await _cases_for_host(ac, host)
        assert len(cases) == 2
        assert {c["status"] for c in cases} == {"CLOSED", "ACTIVE"}

        assert (await ac.put(f"/api/v1/investigation/case/{cid}", json={"status": "BOGUS"})).status_code == 400
