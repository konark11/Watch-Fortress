from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.database import Base, Asset, Port
import rag.query_engine as qe


def test_open_ports_by_port_number(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    monkeypatch.setattr(qe, "_indexed", True)
    monkeypatch.setattr(qe, "ensure_indexed", lambda db: None)

    # Setup assets and ports
    a1 = Asset(id=1, ip_address="192.168.1.10", hostname="web1.local")
    a2 = Asset(id=2, ip_address="192.168.1.20", hostname="web2.local")
    a3 = Asset(id=3, ip_address="192.168.1.30", hostname="db1.local")
    session.add_all([a1, a2, a3])
    session.commit()

    p1 = Port(asset_id=1, port_number=443, protocol="tcp", state="open", service_name="https")
    p2 = Port(asset_id=1, port_number=80, protocol="tcp", state="open", service_name="http")
    p3 = Port(asset_id=2, port_number=443, protocol="tcp", state="open", service_name="https")
    p4 = Port(asset_id=3, port_number=5432, protocol="tcp", state="open", service_name="postgresql")
    session.add_all([p1, p2, p3, p4])
    session.commit()

    # Query 1: How many hosts have port 443 open?
    res_443 = qe.ask(session, "How many hosts have port 443 open?")
    assert "Found **2 host(s)** with port **443** open:" in res_443["answer"]
    assert "web1.local" in res_443["answer"]
    assert "web2.local" in res_443["answer"]
    assert len(res_443["structured_results"]) == 2

    # Query 2: How many hosts have port 80 open?
    res_80 = qe.ask(session, "How many hosts have port 80 open?")
    assert "Found **1 host(s)** with port **80** open:" in res_80["answer"]
    assert "web1.local" in res_80["answer"]
    assert len(res_80["structured_results"]) == 1

    # Query 3: Port not open anywhere
    res_22 = qe.ask(session, "How many hosts have port 22 open?")
    assert "There are **0 hosts** with port **22** recorded as open" in res_22["answer"]

    # Query 4: Host-specific port query
    res_host_open = qe.ask(session, "Is port 443 open on 192.168.1.10?")
    assert "Yes, port **443/tcp**" in res_host_open["answer"]
    assert "is **open**" in res_host_open["answer"]

    res_host_closed = qe.ask(session, "Is port 22 open on 192.168.1.10?")
    assert "No, port **22** is not open" in res_host_closed["answer"]
    assert "80/tcp" in res_host_closed["answer"]
    assert "443/tcp" in res_host_closed["answer"]

    # Query 5: Asset inventory count
    res_assets = qe.ask(session, "How many assets were scanned?")
    assert "Found **3 asset(s)** in the inventory:" in res_assets["answer"]

    # Query 6: Exclusion query (apart from port 80)
    res_apart = qe.ask(session, "what ports are opened apart from port 80 in other scans")
    assert "excluding port **80**" in res_apart["answer"]
    assert "Port 443" in res_apart["answer"]
    assert "Port 5432" in res_apart["answer"]
    assert "Port 80" not in res_apart["answer"]

    # Query 7: Conceptual question (what is port 80 and what it does?)
    class MockProvider:
        name = "mock"
        def generate(self, *args, **kwargs):
            return "mock"
        def generate_general(self, q, history=None):
            return "Port 80 is used for HTTP web traffic."

    import rag.retrieval.service as ret_service
    monkeypatch.setattr(ret_service, "retrieve", lambda db, q, criteria=None, k=20: [])
    monkeypatch.setattr(qe, "get_provider", lambda: MockProvider())
    monkeypatch.setattr(qe, "validate_provider_configuration", lambda: None)
    res_concept = qe.ask(session, "what is port 80 and what it does?")
    assert res_concept["source_mode"] == "general"
    assert "Port 80 is used for HTTP web traffic." in res_concept["answer"]
