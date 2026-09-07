"""Validation of the authenticated, bounded engine-state inventory endpoint."""
from uuid import UUID

MAX_ENGINE_SNAPSHOT_ROWS = 10000
from lightbulb.company_engine_core import stable_digest, parsed

def validate_inventory(output, *, company_id=None, tenant_id=None, project_id=None, engine=None):
    if output.get("schema") != "lightbulb.sdk_engine_inventory.v1":
        raise ValueError("ENGINE_INVENTORY_SCHEMA")
    from hashlib import sha256
    import re
    for key, expected in (("company_sha256",company_id),("tenant_sha256",tenant_id)):
        if not isinstance(output.get(key),str) or not re.fullmatch("[0-9a-f]{64}",output[key]):
            raise ValueError("ENGINE_INVENTORY_SCOPE_REQUIRED")
        if expected is not None and output[key] != sha256(str(UUID(str(expected))).encode()).hexdigest():
            raise ValueError("ENGINE_INVENTORY_SCOPE_MISMATCH")
    if project_id is not None and str(UUID(output["project_id"])) != str(UUID(str(project_id))):
        raise ValueError("ENGINE_INVENTORY_SCOPE_MISMATCH")
    if output.get("evidence_sha256") != stable_digest({k:v for k,v in output.items() if k != "evidence_sha256"}):
        raise ValueError("ENGINE_INVENTORY_DIGEST_MISMATCH")
    if not isinstance(output.get("engine"),str) or not re.fullmatch("[a-z][a-z0-9_]{0,79}",output["engine"]):
        raise ValueError("ENGINE_INVENTORY_ENGINE_REQUIRED")
    if engine is not None and output["engine"] != engine:
        raise ValueError("ENGINE_INVENTORY_ENGINE_MISMATCH")
    UUID(output["project_id"])
    if output.get("source_coverage", "persisted_sdk_engine_states_only") != "persisted_sdk_engine_states_only":
        raise ValueError("ENGINE_INVENTORY_SOURCE_COVERAGE_INVALID")
    rows=output["records"]
    if not isinstance(rows,list) or type(output.get("row_count")) is not int or len(rows)!=output["row_count"] or len(rows)>MAX_ENGINE_SNAPSHOT_ROWS:
        raise ValueError("ENGINE_INVENTORY_COUNT_MISMATCH")
    if type(output.get("exhaustive_read")) is not bool or type(output.get("truncated")) is not bool or output["truncated"]==output["exhaustive_read"]:
        raise ValueError("ENGINE_INVENTORY_COMPLETENESS_REQUIRED")
    for row in rows:
        if not isinstance(row,dict) or set(row)!={"entity_ref","state_digest","plan_digest","status","version"}:
            raise ValueError("ENGINE_INVENTORY_RECORD_INVALID")
        if any(not isinstance(row.get(key),str) or not row[key].strip() for key in ("entity_ref","status")):
            raise ValueError("ENGINE_INVENTORY_RECORD_INVALID")
        if type(row.get("version")) is not int or row["version"]<1:
            raise ValueError("ENGINE_INVENTORY_RECORD_INVALID")
        if any(not isinstance(row.get(key),str) or not re.fullmatch("[0-9a-f]{64}",row[key]) for key in ("state_digest","plan_digest")):
            raise ValueError("ENGINE_INVENTORY_RECORD_INVALID")
    if len({r["entity_ref"] for r in rows}) != len(rows):
        raise ValueError("ENGINE_INVENTORY_DUPLICATE")
    parsed(output["observed_at"])
    return output


class EngineSnapshotRead:
    """Validate contiguous pages of one host-materialized immutable scoped snapshot."""

    def __init__(self, *, company_id, tenant_id, project_id, engine=None, status=None):
        self.company_id, self.tenant_id, self.project_id = company_id, tenant_id, project_id
        self.engine, self.status = engine, status.lower() if status else None
        self.records = []
        self.document = None
        self.next_offset = 0
        self.snapshot_id = None

    def add(self, page):
        from hashlib import sha256
        import re
        if not isinstance(page, dict) or page.get("schema") != "lightbulb.sdk_engine_state_snapshot_page.v1":
            raise ValueError("ENGINE_SNAPSHOT_SCHEMA")
        if self.next_offset is None:
            raise ValueError("ENGINE_SNAPSHOT_ALREADY_COMPLETE")
        expected_keys = {"schema","snapshot_id","tenant_sha256","company_sha256","project_id","engine","status",
            "observed_at","expires_at","records","row_count","snapshot_digest","offset","next_offset",
            "page_size","exhaustive_read","truncated","evidence_sha256"}
        if set(page) != expected_keys:
            raise ValueError("ENGINE_SNAPSHOT_FIELDS")
        if page["evidence_sha256"] != stable_digest({k:v for k,v in page.items() if k != "evidence_sha256"}):
            raise ValueError("ENGINE_SNAPSHOT_DIGEST_MISMATCH")
        for key, expected in (("tenant_sha256", self.tenant_id), ("company_sha256", self.company_id)):
            if not isinstance(page[key], str) or not re.fullmatch("[0-9a-f]{64}", page[key]):
                raise ValueError("ENGINE_SNAPSHOT_SCOPE_REQUIRED")
            if expected is not None and page[key] != sha256(str(UUID(str(expected))).encode()).hexdigest():
                raise ValueError("ENGINE_SNAPSHOT_SCOPE_MISMATCH")
        if str(UUID(page["project_id"])) != str(UUID(str(self.project_id))):
            raise ValueError("ENGINE_SNAPSHOT_SCOPE_MISMATCH")
        UUID(page["snapshot_id"])
        if page["engine"] != self.engine or page["status"] != self.status:
            raise ValueError("ENGINE_SNAPSHOT_FILTER_MISMATCH")
        if (type(page["row_count"]) is not int or not 0 <= page["row_count"] <= MAX_ENGINE_SNAPSHOT_ROWS
                or type(page["offset"]) is not int or page["offset"] != self.next_offset
                or page["page_size"] != 200 or type(page["page_size"]) is not int
                or page["exhaustive_read"] is not True or page["truncated"] is not False):
            raise ValueError("ENGINE_SNAPSHOT_INCOMPLETE")
        if parsed(page["observed_at"]) >= parsed(page["expires_at"]):
            raise ValueError("ENGINE_SNAPSHOT_WINDOW_INVALID")
        metadata = {key:value for key,value in page.items() if key not in
            {"schema","records","offset","next_offset","page_size","exhaustive_read","truncated","evidence_sha256"}}
        if self.document is not None and metadata != self.document:
            raise ValueError("ENGINE_SNAPSHOT_CHANGED")
        rows = page["records"]
        remaining = page["row_count"] - page["offset"]
        if not isinstance(rows,list) or len(rows) != min(200, remaining):
            raise ValueError("ENGINE_SNAPSHOT_COUNT_MISMATCH")
        end = page["offset"] + len(rows)
        expected_next = end if end < page["row_count"] else None
        if page["next_offset"] != expected_next or (expected_next is not None and type(page["next_offset"]) is not int):
            raise ValueError("ENGINE_SNAPSHOT_CURSOR_INVALID")
        prior = (self.records[-1]["engine"], self.records[-1]["entity_ref"]) if self.records else None
        for row in rows:
            if not isinstance(row,dict) or row.get("schema") != "lightbulb.sdk_engine_state_record.v1":
                raise ValueError("ENGINE_SNAPSHOT_RECORD_INVALID")
            state = row.get("state")
            if not isinstance(state,dict) or not isinstance(state.get("scope"),dict):
                raise ValueError("ENGINE_SNAPSHOT_RECORD_INVALID")
            key = (row.get("engine"), row.get("entity_ref"))
            if any(not isinstance(value,str) or not value for value in key) or (prior is not None and key <= prior):
                raise ValueError("ENGINE_SNAPSHOT_DUPLICATE_OR_UNORDERED")
            if self.engine is not None and key[0] != self.engine or self.status is not None and row.get("status") != self.status:
                raise ValueError("ENGINE_SNAPSHOT_FILTER_MISMATCH")
            if state["scope"].get("project_id") != page["project_id"] or state["scope"].get("entity_ref") != key[1]:
                raise ValueError("ENGINE_SNAPSHOT_RECORD_SCOPE_MISMATCH")
            if any(row.get(field) != state.get(field) for field in ("state_digest","plan_digest","version","status")):
                raise ValueError("ENGINE_SNAPSHOT_RECORD_MISMATCH")
            prior = key
        self.records.extend(rows)
        self.document, self.snapshot_id, self.next_offset = metadata, page["snapshot_id"], expected_next
        if self.next_offset is None:
            document = {key:value for key,value in metadata.items() if key != "snapshot_digest"}
            document["records"] = self.records
            if stable_digest(document) != metadata["snapshot_digest"]:
                raise ValueError("ENGINE_SNAPSHOT_CONTENT_MISMATCH")
        return self.next_offset
