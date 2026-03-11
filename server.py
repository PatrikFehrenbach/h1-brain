import asyncio
import json
import sqlite3
import os
import httpx
from mcp.server.fastmcp import FastMCP

# HackerOne API credentials (Basic Auth: username + token)
H1_USERNAME = os.environ["H1_USERNAME"]
H1_API_TOKEN = os.environ["H1_API_TOKEN"]
H1_BASE_URL = "https://api.hackerone.com/v1"

_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(_DIR, "h1_data.db")
DISCLOSED_DB_FILE = os.path.join(_DIR, "disclosed_reports.db")
JSON_FILE = os.path.join(_DIR, "h1_data.json")

mcp = FastMCP("h1-brain")


# --- Database ---

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_db():
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            title TEXT,
            state TEXT,
            created_at TEXT,
            bounty_awarded_at TEXT,
            closed_at TEXT,
            program_handle TEXT,
            weakness_name TEXT,
            weakness_cwe TEXT,
            severity_rating TEXT,
            severity_score REAL,
            bounty_amount REAL DEFAULT 0,
            bounty_currency TEXT DEFAULT 'USD',
            vulnerability_information TEXT,
            disclosed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            handle TEXT UNIQUE,
            name TEXT,
            submission_state TEXT,
            offers_bounties INTEGER,
            currency TEXT
        );
        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            program_handle TEXT,
            asset_identifier TEXT,
            asset_type TEXT,
            eligible_for_bounty INTEGER,
            eligible_for_submission INTEGER,
            max_severity TEXT,
            instruction TEXT
        );
        CREATE TABLE IF NOT EXISTS attachments (
            id TEXT PRIMARY KEY,
            report_id TEXT,
            file_name TEXT,
            content_type TEXT,
            file_size INTEGER,
            created_at TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id)
        );
        CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program_handle);
        CREATE INDEX IF NOT EXISTS idx_reports_weakness ON reports(weakness_name);
        CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity_rating);
        CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_handle);
        CREATE INDEX IF NOT EXISTS idx_attachments_report ON attachments(report_id);

    """)
    conn.commit()
    conn.close()


def _get_disclosed_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DISCLOSED_DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_disclosed_db():
    conn = _get_disclosed_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS disclosed_reports (
            id INTEGER PRIMARY KEY,
            title TEXT,
            vulnerability_information TEXT,
            weakness_name TEXT,
            program_handle TEXT,
            asset_identifier TEXT,
            asset_type TEXT,
            cve_ids TEXT,
            bounty_amount REAL
        );
        CREATE INDEX IF NOT EXISTS idx_disclosed_program ON disclosed_reports(program_handle);
        CREATE INDEX IF NOT EXISTS idx_disclosed_weakness ON disclosed_reports(weakness_name);
    """)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS disclosed_reports_fts USING fts5(
            title, vulnerability_information,
            content='disclosed_reports',
            content_rowid='id'
        )
    """)
    conn.commit()
    conn.close()


def _migrate_json():
    """One-time migration from h1_data.json to SQLite."""
    if not os.path.exists(JSON_FILE):
        return
    try:
        with open(JSON_FILE, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return

    conn = _get_db()

    reports = data.get("reports", [])
    for r in reports:
        sev = r.get("severity") or {}
        weakness = r.get("weakness") or {}
        bounty = r.get("bounty") or {}
        conn.execute(
            "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r.get("id"), r.get("title"), r.get("state"), r.get("created_at"),
             r.get("bounty_awarded_at"), r.get("closed_at"), r.get("program_handle"),
             weakness.get("name"), weakness.get("cwe_id"),
             sev.get("rating"), sev.get("score"),
             bounty.get("amount", 0), bounty.get("currency", "USD"),
             None, None),  # vulnerability_information and disclosed_at not in JSON
        )

    programs = data.get("programs", [])
    for p in programs:
        conn.execute(
            "INSERT OR REPLACE INTO programs VALUES (?,?,?,?,?,?)",
            (p.get("id"), p.get("handle"), p.get("name"),
             p.get("submission_state"), 1 if p.get("offers_bounties") else 0,
             p.get("currency")),
        )

    scopes = data.get("scopes", {})
    for handle, scope_list in scopes.items():
        for s in scope_list:
            conn.execute(
                "INSERT OR REPLACE INTO scopes VALUES (?,?,?,?,?,?,?,?)",
                (s.get("id"), handle, s.get("asset_identifier"), s.get("asset_type"),
                 1 if s.get("eligible_for_bounty") else 0,
                 1 if s.get("eligible_for_submission") else 0,
                 s.get("max_severity"), s.get("instruction")),
            )

    conn.commit()
    conn.close()
    os.rename(JSON_FILE, JSON_FILE + ".bak")


# Initialize on import
_init_db()
_init_disclosed_db()
_migrate_json()


# --- API helpers ---

def _auth():
    return (H1_USERNAME, H1_API_TOKEN)


async def _api_get(client: httpx.AsyncClient, path: str, params: dict | None = None) -> httpx.Response:
    for attempt in range(3):
        resp = await client.get(
            f"{H1_BASE_URL}{path}",
            auth=_auth(),
            params=params,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 429:
            await asyncio.sleep(60)
            continue
        resp.raise_for_status()
        return resp
    return resp


async def _fetch_all_pages(path: str, params: dict | None = None) -> list:
    results = []
    page = 1
    params = params or {}
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            params["page[number]"] = page
            params["page[size]"] = 100
            resp = await _api_get(client, path, params)
            body = resp.json()
            data = body.get("data", [])
            if not data:
                break
            results.extend(data)
            if not body.get("links", {}).get("next"):
                break
            page += 1
    return results


async def _fetch_report_detail(client: httpx.AsyncClient, report_id: str) -> dict:
    resp = await _api_get(client, f"/hackers/reports/{report_id}")
    return resp.json().get("data", {})


def _extract_bounty(report_detail: dict) -> tuple[float, str]:
    rels = report_detail.get("relationships", {})
    bounties = rels.get("bounties", {}).get("data", [])
    total = 0.0
    currency = "USD"
    for b in bounties:
        attrs = b.get("attributes", {})
        total += float(attrs.get("awarded_amount", 0))
        currency = attrs.get("awarded_currency", currency)
    return total, currency


def _extract_severity(report: dict) -> tuple[str | None, float | None]:
    rel = report.get("relationships", {})
    sev_data = rel.get("severity", {}).get("data")
    if not sev_data:
        return None, None
    attrs = sev_data.get("attributes", {})
    return attrs.get("rating"), attrs.get("score")


def _extract_program_handle(report: dict) -> str | None:
    rel = report.get("relationships", {})
    return rel.get("program", {}).get("data", {}).get("attributes", {}).get("handle")


def _extract_weakness(report: dict) -> tuple[str | None, str | None]:
    rel = report.get("relationships", {})
    weak_data = rel.get("weakness", {}).get("data")
    if not weak_data:
        return None, None
    attrs = weak_data.get("attributes", {})
    return attrs.get("name"), attrs.get("external_id")


# --- Fetch tools (API -> DB) ---

@mcp.tool()
async def fetch_rewarded_reports() -> str:
    """Sync your personal bounty-awarded reports from HackerOne API into the local database. Run once, re-run to update."""
    all_reports = await _fetch_all_pages("/hackers/me/reports")

    rewarded_basic = [r for r in all_reports if r.get("attributes", {}).get("bounty_awarded_at")]

    rows = []
    async with httpx.AsyncClient(timeout=30) as client:
        sem = asyncio.Semaphore(10)

        async def fetch_one(report):
            async with sem:
                detail = await _fetch_report_detail(client, report["id"])
                attrs = report.get("attributes", {})
                detail_attrs = detail.get("attributes", {})
                bounty_amount, bounty_currency = _extract_bounty(detail)
                sev_rating, sev_score = _extract_severity(detail)
                weak_name, weak_cwe = _extract_weakness(report)
                # Extract attachment metadata
                att_data = detail.get("relationships", {}).get("attachments", {}).get("data", [])
                att_rows = []
                for a in att_data:
                    a_attrs = a.get("attributes", {})
                    att_rows.append((
                        a["id"], report["id"], a_attrs.get("file_name"),
                        a_attrs.get("content_type"), a_attrs.get("file_size"),
                        a_attrs.get("created_at"),
                    ))
                return (
                    (report["id"], attrs.get("title"), attrs.get("state"),
                     attrs.get("created_at"), attrs.get("bounty_awarded_at"), attrs.get("closed_at"),
                     _extract_program_handle(report), weak_name, weak_cwe,
                     sev_rating, sev_score, bounty_amount, bounty_currency,
                     detail_attrs.get("vulnerability_information"),
                     detail_attrs.get("disclosed_at")),
                    att_rows,
                )

        tasks = [fetch_one(r) for r in rewarded_basic]
        results = list(await asyncio.gather(*tasks))

    rows = [r[0] for r in results]
    all_attachments = [a for r in results for a in r[1]]

    conn = _get_db()
    conn.execute("DELETE FROM reports")
    conn.execute("DELETE FROM attachments")
    conn.executemany("INSERT INTO reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.executemany("INSERT INTO attachments VALUES (?,?,?,?,?,?)", all_attachments)
    conn.commit()
    conn.close()

    total_earned = sum(r[11] for r in rows)
    return f"Fetched and stored {len(rows)} rewarded reports (out of {len(all_reports)} total). Total bounties: ${total_earned:,.2f}"


@mcp.tool()
async def fetch_programs() -> str:
    """Sync your accessible HackerOne programs into the local database."""
    all_programs = await _fetch_all_pages("/hackers/programs")

    rows = []
    for prog in all_programs:
        attrs = prog.get("attributes", {})
        rows.append((
            prog["id"], attrs.get("handle"), attrs.get("name"),
            attrs.get("submission_state"), 1 if attrs.get("offers_bounties") else 0,
            attrs.get("currency"),
        ))

    conn = _get_db()
    conn.execute("DELETE FROM programs")
    conn.executemany("INSERT INTO programs VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()

    return f"Fetched and stored {len(rows)} programs."


@mcp.tool()
async def fetch_program_scopes(handle: str) -> str:
    """Fetch scopes for a program from the API. Called automatically by hack().

    Args:
        handle: The program handle
    """
    scopes_raw = await _fetch_all_pages(f"/hackers/programs/{handle}/structured_scopes")

    rows = []
    for scope in scopes_raw:
        attrs = scope.get("attributes", {})
        rows.append((
            scope["id"], handle, attrs.get("asset_identifier"), attrs.get("asset_type"),
            1 if attrs.get("eligible_for_bounty") else 0,
            1 if attrs.get("eligible_for_submission") else 0,
            attrs.get("max_severity"), attrs.get("instruction"),
        ))

    conn = _get_db()
    conn.execute("DELETE FROM scopes WHERE program_handle = ?", (handle,))
    conn.executemany("INSERT INTO scopes VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()

    return f"Fetched and stored {len(rows)} scopes for '{handle}'."


# --- Search tools ---

@mcp.tool()
async def search_reports(
    query: str = "",
    program: str = "",
    weakness: str = "",
    severity: str = "",
    limit: int = 20,
) -> str:
    """Search your personal rewarded reports. For public community reports use search_disclosed_reports.

    Args:
        query: Title search (partial match)
        program: Program handle filter
        weakness: Weakness type filter (e.g. 'XSS', 'SSRF')
        severity: Severity rating (critical, high, medium, low)
        limit: Max results (default 20)
    """
    conn = _get_db()
    conditions = []
    params = []

    if query:
        conditions.append("title LIKE ?")
        params.append(f"%{query}%")
    if program:
        conditions.append("program_handle LIKE ?")
        params.append(f"%{program}%")
    if weakness:
        conditions.append("(weakness_name LIKE ? OR weakness_cwe LIKE ?)")
        params.extend([f"%{weakness}%", f"%{weakness}%"])
    if severity:
        conditions.append("severity_rating = ?")
        params.append(severity.lower())

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM reports WHERE {where} ORDER BY bounty_amount DESC LIMIT ?",
        params,
    ).fetchall()
    conn.close()

    if not rows:
        return "No reports found matching your search."

    total = sum(r["bounty_amount"] for r in rows)
    lines = [f"Found {len(rows)} reports (${total:,.0f} total):", ""]
    for r in rows:
        rating = r["severity_rating"] or "?"
        weak = r["weakness_name"] or ""
        cwe = f" ({r['weakness_cwe']})" if r["weakness_cwe"] else ""
        amount = f"${r['bounty_amount']:,.0f}" if r["bounty_amount"] else "$0"
        lines.append(f"- **#{r['id']}** [{rating}] {r['title']} — {r['program_handle']} — {weak}{cwe} — {amount}")
        # Show snippet of vulnerability info
        vuln = r["vulnerability_information"]
        if vuln:
            snippet = vuln[:200].replace("\n", " ").strip()
            if len(vuln) > 200:
                snippet += "..."
            lines.append(f"  > {snippet}")

    lines.append("")
    lines.append("_Use get_report(id) to read the full vulnerability details._")
    return "\n".join(lines)


@mcp.tool()
async def get_report(report_id: str) -> str:
    """Get full details of your personal report. For public reports use get_disclosed_report.

    Args:
        report_id: The report ID
    """
    conn = _get_db()
    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()

    if not row:
        return f"Report #{report_id} not found in database."

    r = dict(row)
    lines = [
        f"# Report #{r['id']}: {r['title']}",
        "",
        f"**Program:** {r['program_handle']}",
        f"**Severity:** {r['severity_rating']} ({r['severity_score']})" if r['severity_rating'] else "**Severity:** unknown",
        f"**Weakness:** {r['weakness_name']} ({r['weakness_cwe']})" if r['weakness_name'] else "**Weakness:** unknown",
        f"**Bounty:** ${r['bounty_amount']:,.0f} {r['bounty_currency']}" if r['bounty_amount'] else "**Bounty:** $0",
        f"**State:** {r['state']}",
        f"**Created:** {r['created_at']}",
        f"**Bounty awarded:** {r['bounty_awarded_at']}" if r['bounty_awarded_at'] else "",
        f"**Disclosed:** {r['disclosed_at']}" if r['disclosed_at'] else "",
        "",
        "## Vulnerability Details",
        r['vulnerability_information'] if r['vulnerability_information'] else "_No vulnerability details stored. Run fetch_rewarded_reports to pull full report bodies from the API._",
    ]

    # Append attachment list
    conn2 = _get_db()
    att_rows = conn2.execute(
        "SELECT * FROM attachments WHERE report_id = ?", (report_id,)
    ).fetchall()
    conn2.close()
    if att_rows:
        lines.append("")
        lines.append(f"## Attachments ({len(att_rows)})")
        for a in att_rows:
            size_kb = (a['file_size'] or 0) / 1024
            lines.append(f"- **{a['file_name']}** ({a['content_type']}, {size_kb:.0f} KB) — id: {a['id']}")
        lines.append("")
        lines.append("_Use fetch_attachment(report_id, attachment_id) to get a fresh download URL._")

    return "\n".join(line for line in lines if line is not None)


@mcp.tool()
async def fetch_attachment(report_id: str, attachment_id: str = "") -> str:
    """Get fresh download URLs for report attachments (expire in ~1 hour).

    Args:
        report_id: The report ID
        attachment_id: Specific attachment ID, or empty for all
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await _api_get(client, f"/hackers/reports/{report_id}")
    detail = resp.json().get("data", {})
    att_data = detail.get("relationships", {}).get("attachments", {}).get("data", [])

    if not att_data:
        return f"No attachments found for report #{report_id}."

    if attachment_id:
        att_data = [a for a in att_data if a["id"] == attachment_id]
        if not att_data:
            return f"Attachment {attachment_id} not found on report #{report_id}."

    lines = [f"## Attachments for Report #{report_id}", ""]
    for a in att_data:
        attrs = a.get("attributes", {})
        size_kb = (attrs.get("file_size") or 0) / 1024
        lines.append(f"### {attrs.get('file_name')} ({attrs.get('content_type')}, {size_kb:.0f} KB)")
        lines.append(f"**Download URL** (expires in ~1 hour):")
        lines.append(attrs.get("expiring_url", "N/A"))
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
async def search_programs(query: str = "", bounty_only: bool = False, limit: int = 20) -> str:
    """Search your stored programs by handle or name.

    Args:
        query: Program handle or name (partial match)
        bounty_only: Only bounty programs
        limit: Max results (default 20)
    """
    conn = _get_db()
    conditions = []
    params = []

    if query:
        conditions.append("(handle LIKE ? OR name LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if bounty_only:
        conditions.append("offers_bounties = 1")

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM programs WHERE {where} ORDER BY handle LIMIT ?",
        params,
    ).fetchall()
    conn.close()

    if not rows:
        return "No programs found."

    lines = [f"Found {len(rows)} programs:", ""]
    for p in rows:
        bounty_tag = " [bounty]" if p["offers_bounties"] else ""
        lines.append(f"- {p['handle']} — {p['name']}{bounty_tag} ({p['submission_state']})")

    return "\n".join(lines)


@mcp.tool()
async def search_scopes(
    program: str = "",
    asset: str = "",
    bounty_only: bool = False,
    limit: int = 30,
) -> str:
    """Search in-scope assets across programs.

    Args:
        program: Program handle filter
        asset: Asset identifier (partial match)
        bounty_only: Only bounty-eligible assets
        limit: Max results (default 30)
    """
    conn = _get_db()
    conditions = []
    params = []

    if program:
        conditions.append("program_handle LIKE ?")
        params.append(f"%{program}%")
    if asset:
        conditions.append("asset_identifier LIKE ?")
        params.append(f"%{asset}%")
    if bounty_only:
        conditions.append("eligible_for_bounty = 1")

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM scopes WHERE {where} ORDER BY program_handle, asset_identifier LIMIT ?",
        params,
    ).fetchall()
    conn.close()

    if not rows:
        return "No scopes found."

    lines = [f"Found {len(rows)} assets:", ""]
    for s in rows:
        bounty_tag = " [bounty]" if s["eligible_for_bounty"] else ""
        lines.append(f"- `{s['asset_identifier']}` ({s['asset_type']}) — {s['program_handle']}{bounty_tag} [max: {s['max_severity']}]")

    return "\n".join(lines)


@mcp.tool()
async def get_report_summary() -> str:
    """Summary of your rewarded reports grouped by program with totals."""
    conn = _get_db()
    rows = conn.execute("""
        SELECT program_handle, COUNT(*) as cnt, SUM(bounty_amount) as total
        FROM reports GROUP BY program_handle ORDER BY total DESC
    """).fetchall()

    if not rows:
        conn.close()
        return "No stored reports. Run fetch_rewarded_reports first."

    grand_total = sum(r["total"] for r in rows)
    grand_count = sum(r["cnt"] for r in rows)
    lines = [f"Total: {grand_count} reports, ${grand_total:,.0f} earned", ""]

    for r in rows:
        handle = r["program_handle"] or "Unknown"
        lines.append(f"- **{handle}**: {r['cnt']} reports, ${r['total']:,.0f}")

    conn.close()
    return "\n".join(lines)


# --- Disclosed reports tools ---

@mcp.tool()
async def search_disclosed_reports(
    query: str = "",
    program: str = "",
    weakness: str = "",
    limit: int = 20,
) -> str:
    """Search public disclosed reports from other researchers that paid a bounty. For your own reports use search_reports.

    Args:
        query: Full-text search in title and vulnerability write-up
        program: Program handle filter
        weakness: Weakness type filter (e.g. 'XSS', 'SSRF')
        limit: Max results (default 20)
    """
    conn = _get_disclosed_db()

    if query:
        # FTS5 search, optionally filtered
        conditions = []
        params = []

        if program:
            conditions.append("d.program_handle LIKE ?")
            params.append(f"%{program}%")
        if weakness:
            conditions.append("d.weakness_name LIKE ?")
            params.append(f"%{weakness}%")

        where_extra = (" AND " + " AND ".join(conditions)) if conditions else ""
        params = [query] + params + [limit]

        rows = conn.execute(f"""
            SELECT d.*, rank FROM disclosed_reports_fts fts
            JOIN disclosed_reports d ON d.id = fts.rowid
            WHERE disclosed_reports_fts MATCH ?{where_extra}
            ORDER BY d.id DESC
            LIMIT ?
        """, params).fetchall()
    else:
        conditions = []
        params = []
        if program:
            conditions.append("program_handle LIKE ?")
            params.append(f"%{program}%")
        if weakness:
            conditions.append("weakness_name LIKE ?")
            params.append(f"%{weakness}%")

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        rows = conn.execute(
            f"SELECT * FROM disclosed_reports WHERE {where} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()

    conn.close()

    if not rows:
        return "No disclosed reports found matching your search."

    lines = [f"Found {len(rows)} disclosed reports:", ""]
    for r in rows:
        weak = r["weakness_name"] or "unknown"
        asset = r["asset_identifier"] or ""
        cves = json.loads(r["cve_ids"] or "[]")
        cve_str = f" [{', '.join(cves)}]" if cves else ""
        bounty_str = f" — ${r['bounty_amount']:,.0f}" if r["bounty_amount"] else ""
        lines.append(f"- **#{r['id']}** {r['title']} — {r['program_handle']} — {weak}{cve_str}{bounty_str}")
        if asset:
            lines.append(f"  Asset: `{asset}` ({r['asset_type']})")
        vuln = r["vulnerability_information"]
        if vuln:
            snippet = vuln[:200].replace("\n", " ").strip()
            if len(vuln) > 200:
                snippet += "..."
            lines.append(f"  > {snippet}")

    lines.append("")
    lines.append("_Use get_disclosed_report(id) for full details._")
    return "\n".join(lines)


@mcp.tool()
async def get_disclosed_report(report_id: int) -> str:
    """Get full details of a public disclosed report. For your own reports use get_report.

    Args:
        report_id: The report ID
    """
    conn = _get_disclosed_db()
    row = conn.execute("SELECT * FROM disclosed_reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()

    if not row:
        return f"Disclosed report #{report_id} not found in database."

    r = dict(row)
    cves = json.loads(r["cve_ids"] or "[]")
    lines = [
        f"# Disclosed Report #{r['id']}: {r['title']}",
        "",
        f"**Program:** {r['program_handle']}",
        f"**Weakness:** {r['weakness_name'] or 'unknown'}",
        f"**Bounty:** ${r['bounty_amount']:,.0f}" if r["bounty_amount"] else "**Bounty:** undisclosed",
        f"**Asset:** `{r['asset_identifier']}` ({r['asset_type']})" if r["asset_identifier"] else "",
        f"**CVEs:** {', '.join(cves)}" if cves else "",
        "",
        "## Vulnerability Details",
        r["vulnerability_information"] or "_No details available._",
    ]
    return "\n".join(line for line in lines if line is not None)


# --- Hack tool ---

@mcp.tool()
async def hack(handle: str) -> str:
    """Start a hacking session. Fetches fresh scope, cross-references your reports and public disclosures, returns an actionable attack briefing.

    Args:
        handle: The program handle
    """
    # 1. Fetch fresh scopes from API and store
    scopes_raw = await _fetch_all_pages(f"/hackers/programs/{handle}/structured_scopes")
    scope_rows = []
    for scope in scopes_raw:
        attrs = scope.get("attributes", {})
        scope_rows.append((
            scope["id"], handle, attrs.get("asset_identifier"), attrs.get("asset_type"),
            1 if attrs.get("eligible_for_bounty") else 0,
            1 if attrs.get("eligible_for_submission") else 0,
            attrs.get("max_severity"), attrs.get("instruction"),
        ))

    conn = _get_db()
    conn.execute("DELETE FROM scopes WHERE program_handle = ?", (handle,))
    conn.executemany("INSERT INTO scopes VALUES (?,?,?,?,?,?,?,?)", scope_rows)
    conn.commit()

    # 2. Read scopes back as dicts
    scopes = [dict(r) for r in conn.execute(
        "SELECT * FROM scopes WHERE program_handle = ?", (handle,)
    ).fetchall()]

    # 3. Get reports
    all_reports = [dict(r) for r in conn.execute("SELECT * FROM reports").fetchall()]
    program_reports = [r for r in all_reports if r["program_handle"] == handle]
    conn.close()

    # 4. Build scope sections
    bounty_scopes = [s for s in scopes if s["eligible_for_bounty"] and s["eligible_for_submission"]]
    no_bounty_scopes = [s for s in scopes if not s["eligible_for_bounty"] and s["eligible_for_submission"]]

    def format_scope(s):
        line = f"- `{s['asset_identifier']}` ({s['asset_type']}) [max: {s['max_severity']}]"
        if s.get("instruction"):
            line += f" — {s['instruction']}"
        return line

    # 5. Past findings
    total_bounty = sum(r["bounty_amount"] for r in program_reports)
    finding_lines = []
    for r in program_reports:
        rating = r["severity_rating"] or "?"
        amount = f"${r['bounty_amount']:,.0f}" if r["bounty_amount"] else "$0"
        weak_str = ""
        if r["weakness_name"]:
            weak_str = f" — {r['weakness_name']}"
            if r["weakness_cwe"]:
                weak_str += f" ({r['weakness_cwe']})"
        finding_lines.append(f"- [{rating}] {r['title']}{weak_str} — {amount}")

    # 6. Weakness types that worked here
    weakness_counts: dict[str, int] = {}
    for r in program_reports:
        if r["weakness_name"]:
            weakness_counts[r["weakness_name"]] = weakness_counts.get(r["weakness_name"], 0) + 1
    weakness_lines = [f"- {name}: {count}x" for name, count in sorted(weakness_counts.items(), key=lambda x: -x[1])]

    # 7. Untouched scope
    untouched = []
    for s in bounty_scopes:
        ident = s["asset_identifier"].lower()
        mentioned = any(ident in r["title"].lower() for r in program_reports if r["title"])
        if not mentioned:
            untouched.append(s)
    untouched_lines = [f"- `{s['asset_identifier']}` ({s['asset_type']}, bounty eligible)" for s in untouched]

    # 8. Suggested attack vectors — weaknesses rewarded on OTHER programs but not here
    local_weakness_names = set(weakness_counts.keys())
    global_weakness_map: dict[str, list[str]] = {}
    for r in all_reports:
        if r["weakness_name"] and r["program_handle"] and r["program_handle"] != handle:
            name = r["weakness_name"]
            prog = r["program_handle"]
            if name not in global_weakness_map:
                global_weakness_map[name] = []
            if prog not in global_weakness_map[name]:
                global_weakness_map[name].append(prog)

    suggestions = []
    for name, programs in sorted(global_weakness_map.items(), key=lambda x: -len(x[1])):
        if name not in local_weakness_names:
            progs_str = ", ".join(programs[:5])
            suggestions.append(f"- {name} (rewarded {len(programs)}x on: {progs_str})")

    # 9. Cross-reference disclosed reports for this program
    disclosed_lines = []
    disclosed_weakness_counts: dict[str, int] = {}
    conn2 = _get_disclosed_db()
    disclosed_count = conn2.execute(
        "SELECT COUNT(*) FROM disclosed_reports WHERE program_handle = ?", (handle,)
    ).fetchone()[0]
    if disclosed_count:
        disclosed_rows = conn2.execute(
            "SELECT id, title, weakness_name, asset_identifier FROM disclosed_reports WHERE program_handle = ? ORDER BY id DESC LIMIT 20",
            (handle,),
        ).fetchall()
        for dr in disclosed_rows:
            weak = dr["weakness_name"] or "unknown"
            asset = dr["asset_identifier"] or ""
            asset_str = f" on `{asset}`" if asset else ""
            disclosed_lines.append(f"- #{dr['id']} {dr['title']} — {weak}{asset_str}")
            if dr["weakness_name"]:
                disclosed_weakness_counts[dr["weakness_name"]] = disclosed_weakness_counts.get(dr["weakness_name"], 0) + 1

        # Get full weakness breakdown
        all_disclosed_weaknesses = conn2.execute(
            "SELECT weakness_name, COUNT(*) as cnt FROM disclosed_reports WHERE program_handle = ? AND weakness_name IS NOT NULL GROUP BY weakness_name ORDER BY cnt DESC",
            (handle,),
        ).fetchall()
        disclosed_weakness_counts = {r["weakness_name"]: r["cnt"] for r in all_disclosed_weaknesses}
    conn2.close()

    # 10. Build briefing
    lines = [f"# Hacking Session: {handle}", ""]

    lines.append("## Scope")
    if bounty_scopes:
        lines.append("### In-Scope (Bounty Eligible)")
        lines.extend(format_scope(s) for s in bounty_scopes)
    if no_bounty_scopes:
        lines.append("\n### In-Scope (No Bounty)")
        lines.extend(format_scope(s) for s in no_bounty_scopes)
    if not bounty_scopes and not no_bounty_scopes:
        lines.append("No scopes found for this program.")

    lines.append("")
    lines.append(f"## Your Past Findings Here ({len(program_reports)} reports, ${total_bounty:,.0f} total)")
    if finding_lines:
        lines.extend(finding_lines)
    else:
        lines.append("No rewarded reports on this program yet.")

    if weakness_lines:
        lines.append("")
        lines.append("## Weakness Types That Worked Here")
        lines.extend(weakness_lines)

    lines.append("")
    lines.append("## Untouched Scope")
    lines.append("Assets with zero findings from you:")
    if untouched_lines:
        lines.extend(untouched_lines)
    else:
        lines.append("All bounty-eligible assets have been tested.")

    if suggestions:
        lines.append("")
        lines.append("## Suggested Attack Vectors")
        lines.append("Based on your global track record, these weakness types have paid off")
        lines.append("on other programs but haven't been found here yet:")
        lines.extend(suggestions)

    if disclosed_lines:
        lines.append("")
        lines.append(f"## Public Disclosed Reports ({disclosed_count} total for this program)")
        lines.append("What other researchers found here (bounty-awarded, publicly disclosed):")
        lines.extend(disclosed_lines)
        if disclosed_count > 20:
            lines.append(f"_...and {disclosed_count - 20} more. Use search_disclosed_reports(program='{handle}') to see all._")
        if disclosed_weakness_counts:
            lines.append("")
            lines.append("### Weakness patterns from public disclosures")
            for name, cnt in sorted(disclosed_weakness_counts.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"- {name}: {cnt}x")

    instructions_path = os.path.join(_DIR, "hack_instructions.md")
    with open(instructions_path, "r") as f:
        instructions = f.read().replace("{handle}", handle)
    lines.append("")
    lines.append(instructions)

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
