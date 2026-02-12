#!/usr/bin/env python3
"""
Generate vulnerability summary reports from repo_context.db

Usage:
    python generate_vuln_reports.py /path/to/repo_context.db

This will create:
- vulns/threat-model.md (architectural info, entry points)
- vulns/<id>/summary.md (vulnerability-specific details)
"""

import argparse
import sqlite3
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def get_component_data(db_path: Path):
    """Query the database for all component/architectural data."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get all components that have vulnerabilities
    cursor.execute("""
        SELECT DISTINCT
            app.id,
            app.repo,
            app.location,
            app.notes,
            app.is_app,
            app.is_library
        FROM application app
        INNER JOIN audit_result ar ON app.id = ar.component_id
        WHERE ar.has_vulnerability = 1
        ORDER BY app.repo, app.id
    """)
    components = [dict(row) for row in cursor.fetchall()]

    # For each component, get entry points and web entry points
    for comp in components:
        cursor.execute("""
            SELECT id, file, line, user_input, notes
            FROM entry_point
            WHERE app_id = ?
            ORDER BY id
        """, (comp['id'],))
        comp['entry_points'] = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT id, method, path, component, auth, middleware, roles_scopes, entry_point_id, notes
            FROM web_entry_point
            WHERE component = ?
            ORDER BY id
        """, (comp['id'],))
        comp['web_entry_points'] = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return components


def get_vulnerability_data(db_path: Path):
    """Query the database for all vulnerabilities."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
    SELECT
        ar.id,
        ar.repo,
        ar.component_id,
        ar.issue_type,
        ar.issue_id,
        ar.has_vulnerability,
        ar.has_non_security_error,
        ar.notes as audit_notes,
        app.location as component_location,
        ai.notes as issue_notes
    FROM audit_result ar
    LEFT JOIN application app ON ar.component_id = app.id
    LEFT JOIN application_issue ai ON ar.issue_id = ai.id
    WHERE ar.has_vulnerability = 1
    ORDER BY ar.id
    """

    cursor.execute(query)
    vulnerabilities = []

    for vuln in cursor.fetchall():
        vuln_dict = dict(vuln)

        # Check for low severity reasons
        cursor.execute("""
            SELECT reason
            FROM low_severity_audit_result
            WHERE result_id = ?
        """, (vuln['id'],))
        low_sev = cursor.fetchone()
        vuln_dict['low_severity_reason'] = low_sev['reason'] if low_sev else None

        vulnerabilities.append(vuln_dict)

    conn.close()
    return vulnerabilities


def generate_threat_model(components: list) -> str:
    """Generate a threat model markdown document."""
    md = []

    md.append("# Threat Model & Architecture")
    md.append("")
    md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    md.append("")
    md.append("This document contains architectural information, entry points, and threat model data for all components analyzed during the security audit.")
    md.append("")
    md.append("---")
    md.append("")

    # Group components by repository
    repos = defaultdict(list)
    for comp in components:
        repos[comp['repo']].append(comp)

    for repo, repo_components in sorted(repos.items()):
        md.append(f"## Repository: `{repo}`")
        md.append("")

        for comp in repo_components:
            md.append(f"### Component {comp['id']}: `{comp['location']}`")
            md.append("")

            # Component type
            comp_types = []
            if comp['is_app']:
                comp_types.append("Application")
            if comp['is_library']:
                comp_types.append("Library")

            if comp_types:
                md.append(f"**Type:** {', '.join(comp_types)}  ")
                md.append("")

            # Component description
            if comp['notes']:
                md.append("#### Architecture & Description")
                md.append("")
                md.append(comp['notes'])
                md.append("")

            # Entry points
            if comp['entry_points']:
                md.append(f"#### Entry Points ({len(comp['entry_points'])} total)")
                md.append("")

                for ep in comp['entry_points']:
                    md.append(f"##### Entry Point {ep['id']}")
                    md.append("")
                    md.append(f"- **File:** `{ep['file']}:{ep['line']}`")
                    md.append(f"- **User Input:** `{ep['user_input']}`")
                    if ep['notes']:
                        md.append("")
                        md.append(ep['notes'])
                    md.append("")

            # Web entry points
            if comp['web_entry_points']:
                md.append(f"#### Web Entry Points ({len(comp['web_entry_points'])} total)")
                md.append("")

                for wep in comp['web_entry_points']:
                    md.append(f"##### `{wep['method']} {wep['path']}`")
                    md.append("")
                    if wep['auth']:
                        md.append(f"- **Authentication:** {wep['auth']}")
                    if wep['middleware']:
                        md.append(f"- **Middleware:** {wep['middleware']}")
                    if wep['roles_scopes']:
                        md.append(f"- **Roles/Scopes:** {wep['roles_scopes']}")
                    if wep['notes']:
                        md.append("")
                        md.append(wep['notes'])
                    md.append("")

            md.append("---")
            md.append("")

    md.append("*This threat model was automatically generated by the SecLab Taskflows audit system.*")
    return "\n".join(md)


def generate_vulnerability_report(vuln_data: dict) -> str:
    """Generate a focused vulnerability report."""
    md = []

    # Header
    md.append(f"# {vuln_data['issue_type']}")
    md.append("")
    md.append(f"**Vulnerability ID:** `{vuln_data['id']}`  ")
    md.append(f"**Repository:** `{vuln_data['repo']}`  ")
    md.append(f"**Component ID:** `{vuln_data['component_id']}`  ")
    md.append(f"**Component Location:** `{vuln_data['component_location']}`  ")
    md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    md.append("")

    # Severity indicators
    severity_badges = []
    if vuln_data['has_vulnerability']:
        severity_badges.append("🔴 **TRUE POSITIVE**")
    if vuln_data['has_non_security_error']:
        severity_badges.append("🟡 **NON-SECURITY ERROR PRESENT**")
    if vuln_data['low_severity_reason']:
        severity_badges.append("🔵 **LOW SEVERITY**")

    if severity_badges:
        md.append(" | ".join(severity_badges))
        md.append("")

    # Reference to threat model
    md.append("---")
    md.append("")
    md.append("📋 **For architectural context, entry points, and threat model details, see [`../threat-model.md`](../threat-model.md)**")
    md.append("")
    md.append("---")
    md.append("")

    # Low severity reason if applicable
    if vuln_data['low_severity_reason']:
        md.append("## Low Severity Justification")
        md.append("")
        md.append(vuln_data['low_severity_reason'])
        md.append("")
        md.append("---")
        md.append("")

    # Issue context
    if vuln_data['issue_notes']:
        md.append("## Issue Context")
        md.append("")
        md.append(vuln_data['issue_notes'])
        md.append("")
        md.append("---")
        md.append("")

    # Audit findings (main vulnerability details)
    md.append("## Vulnerability Analysis")
    md.append("")
    md.append(vuln_data['audit_notes'])
    md.append("")

    # Footer
    md.append("---")
    md.append("")
    md.append("*This vulnerability report was automatically generated by the SecLab Taskflows audit system.*")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(
        description="Generate vulnerability summary reports from repo_context.db"
    )
    parser.add_argument(
        "database",
        type=Path,
        help="Path to repo_context.db file"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        help="Output directory (default: vulns/ adjacent to database)"
    )

    args = parser.parse_args()

    db_path = args.database.resolve()
    if not db_path.exists():
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir.resolve()
    else:
        output_dir = db_path.parent / "vulns"

    print(f"Reading data from: {db_path}")
    print(f"Output directory: {output_dir}")
    print()

    # Get component and vulnerability data
    try:
        components = get_component_data(db_path)
        vulnerabilities = get_vulnerability_data(db_path)
    except Exception as e:
        print(f"Error reading database: {e}", file=sys.stderr)
        sys.exit(1)

    if not vulnerabilities:
        print("No vulnerabilities found (has_vulnerability=1) in database.")
        return

    print(f"Found {len(vulnerabilities)} vulnerability/vulnerabilities")
    print(f"Found {len(components)} component(s) with architectural data")
    print()

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate threat model
    print("Generating threat model...")
    threat_model = generate_threat_model(components)
    threat_model_path = output_dir / "threat-model.md"
    threat_model_path.write_text(threat_model, encoding='utf-8')
    print(f"✓ Generated: {threat_model_path.relative_to(output_dir.parent)}")
    print()

    # Generate individual vulnerability reports
    print("Generating vulnerability reports...")
    for vuln in vulnerabilities:
        vuln_id = vuln['id']
        vuln_dir = output_dir / str(vuln_id)
        vuln_dir.mkdir(parents=True, exist_ok=True)

        summary_path = vuln_dir / "summary.md"
        markdown = generate_vulnerability_report(vuln)
        summary_path.write_text(markdown, encoding='utf-8')

        issue_type_short = vuln['issue_type'][:50]
        print(f"  ✓ {vuln_id}/summary.md - {issue_type_short}")

    print()
    print(f"Successfully generated:")
    print(f"  - 1 threat model document")
    print(f"  - {len(vulnerabilities)} vulnerability report(s)")
    print(f"  - All saved to: {output_dir}")


if __name__ == "__main__":
    main()
