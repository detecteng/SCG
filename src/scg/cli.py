"""
SCG CLI — entry point registered as `scg` in pyproject.toml.

Commands:
    scg init
    scg seed [--db PATH]
    scg query app  <app_id>  [--db PATH]
    scg query ttp  <ttp_id>  [--db PATH]
    scg gaps detection             [--app APP_ID] [--db PATH]
    scg gaps mitigation            [--app APP_ID] [--db PATH]
    scg gaps mitre-recommendations [--app APP_ID] [--format table|json|csv] [--db PATH]
    scg gaps false-coverage        [--app APP_ID] [--db PATH]
    scg recompute [--ti TI_ID]         [--db PATH]
    scg sql "<SQL>"  [--format table|json|csv] [--db PATH]
    scg sql -        (read SQL from stdin)
"""

from __future__ import annotations

import argparse
import csv as _csv
import json
import os
import sqlite3
import sys
from typing import Any

from scg.graph import SCG
from scg.seed import load_seed


# ------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------

def _fmt_table(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    if not rows:
        return "(no rows)"
    cols = columns or list(rows[0].keys())
    widths = {c: len(c) for c in cols}
    for row in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    sep    = "  ".join("-" * widths[c] for c in cols)
    lines  = [header, sep]
    for row in rows:
        lines.append("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols))
    return "\n".join(lines)


def _bool_icon(val: Any) -> str:
    return "✓" if val else "✗"


def _coverage_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        # effective status (§3.2); "*" marks an engineer override
        state = r["effective_status"] + ("*" if r.get("override_status") else "")
        out.append({
            "id":          r["id"],
            "priority":    r.get("priority", ""),
            "has_det":     _bool_icon(r["has_detection"]),
            "has_ctrl":    _bool_icon(r["has_control"]),
            "confidence":  f"{r['effective_confidence']:.2f}" if r.get("effective_confidence") else "—",
            "state":       state,
            "ttp_name":    r.get("ttp_name", r.get("ttp_id", "")),
            "app_name":    r.get("app_name", r.get("app_id", "")),
        })
    return out


# ------------------------------------------------------------------
# Sub-command handlers
# ------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    with SCG(args.db):
        pass  # schema applied in __init__
    print(f"Initialized schema in {args.db!r}.")


def cmd_seed(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        load_seed(g)
    print(f"Seed data loaded into {args.db!r}.")


def cmd_query_app(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.get_coverage_for_app(args.app_id)
    if not rows:
        print(f"No ThreatInstances found for app '{args.app_id}'.")
        return
    cols = ["id", "priority", "has_det", "has_ctrl", "confidence", "state", "ttp_name"]
    print(f"\nCoverage for app: {args.app_id}\n")
    print(_fmt_table(_coverage_summary(rows), cols))
    print(f"\n{len(rows)} threat instance(s).")


def cmd_query_ttp(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.get_coverage_for_ttp(args.ttp_id)
    if not rows:
        print(f"No ThreatInstances found for TTP '{args.ttp_id}'.")
        return
    cols = ["id", "priority", "has_det", "has_ctrl", "confidence", "state", "app_name"]
    print(f"\nCoverage for TTP: {args.ttp_id}\n")
    print(_fmt_table(_coverage_summary(rows), cols))
    print(f"\n{len(rows)} threat instance(s).")


def cmd_gaps_detection(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.list_detection_gaps(getattr(args, "app", None))
    label = f" for app '{args.app}'" if getattr(args, "app", None) else ""
    print(f"\nDetection gaps{label}:\n")
    if not rows:
        print("(none — full detection coverage)")
        return
    cols = ["id", "priority", "app_name", "ttp_name", "mitre_id", "has_control"]
    display = [
        {**r, "has_control": _bool_icon(r["has_control"])} for r in rows
    ]
    print(_fmt_table(display, cols))
    print(f"\n{len(rows)} gap(s).")


def cmd_gaps_mitigation(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.list_mitigation_gaps(getattr(args, "app", None))
    label = f" for app '{args.app}'" if getattr(args, "app", None) else ""
    print(f"\nMitigation gaps{label}:\n")
    if not rows:
        print("(none — full mitigation coverage)")
        return
    cols = ["id", "priority", "app_name", "ttp_name", "mitre_id", "has_detection"]
    display = [
        {**r, "has_detection": _bool_icon(r["has_detection"])} for r in rows
    ]
    print(_fmt_table(display, cols))
    print(f"\n{len(rows)} gap(s).")


def cmd_gaps_mitre_recommendations(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.list_mitre_recommendation_gaps(getattr(args, "app", None))
    label = f" for app '{args.app}'" if getattr(args, "app", None) else ""
    print(f"\nMITRE recommendation gaps{label}:\n")
    if not rows:
        print("(none — every MITRE-recommended mitigation has a matching control_instance)")
        return
    fmt = getattr(args, "format", "table") or "table"
    if fmt == "json":
        import json as _json
        print(_json.dumps(rows, indent=2))
    elif fmt == "csv":
        if rows:
            keys = list(rows[0].keys())
            print(",".join(keys))
            for r in rows:
                print(",".join(str(r.get(k, "")).replace(",", " ") for k in keys))
    else:
        cols = ["app_name", "ttp_mitre_id", "ttp_name", "mitigation_mitre_id", "mitigation_name"]
        print(_fmt_table(rows, cols))
    print(f"\n{len(rows)} gap(s).")


def cmd_gaps_false_coverage(args: argparse.Namespace) -> None:
    with SCG(args.db) as g:
        rows = g.false_coverage_check(getattr(args, "app", None))
    label = f" for app '{args.app}'" if getattr(args, "app", None) else ""
    print(f"\nFalse coverage check{label}:\n")
    if not rows:
        print("(no false coverage detected)")
        return
    cols = ["threat_instance_id", "app_name", "detection_name", "telemetry_name", "source_system"]
    print(_fmt_table(rows, cols))
    print(f"\n{len(rows)} false-coverage instance(s).")


def cmd_sql(args: argparse.Namespace) -> None:
    sql = sys.stdin.read() if args.sql == "-" else args.sql
    try:
        with SCG(args.db) as g:
            rows, rowcount = g.execute_sql(sql)
    except sqlite3.Error as e:
        print(f"SQL error: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        msg = f"OK — {rowcount} row(s) affected." if rowcount >= 0 else "OK."
        print(msg)
        return

    if args.format == "json":
        print(json.dumps(rows, indent=2, default=str))
    elif args.format == "csv":
        writer = _csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    else:
        print(_fmt_table(rows))
        print(f"\n{len(rows)} row(s).")


def cmd_recompute(args: argparse.Namespace) -> None:
    ti_id = getattr(args, "ti", None)
    with SCG(args.db) as g:
        g.recompute_coverage(ti_id)
    if ti_id:
        print(f"Coverage recomputed for ThreatInstance '{ti_id}'.")
    else:
        print("Coverage recomputed for all ThreatInstances.")


# ------------------------------------------------------------------
# Parser construction
# ------------------------------------------------------------------

def _add_db_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--db",
        default=os.environ.get("SCG_DB_PATH", "scg.db"),
        metavar="PATH",
        help="Path to the SQLite database (default: $SCG_DB_PATH or scg.db)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scg",
        description="Security Coverage Graph — local CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Initialize the database schema")
    _add_db_arg(p_init)
    p_init.set_defaults(func=cmd_init)

    # seed
    p_seed = sub.add_parser("seed", help="Load seed dataset")
    _add_db_arg(p_seed)
    p_seed.set_defaults(func=cmd_seed)

    # query
    p_query = sub.add_parser("query", help="Coverage queries")
    q_sub = p_query.add_subparsers(dest="query_type", required=True)

    p_q_app = q_sub.add_parser("app", help="Coverage for an app")
    p_q_app.add_argument("app_id")
    _add_db_arg(p_q_app)
    p_q_app.set_defaults(func=cmd_query_app)

    p_q_ttp = q_sub.add_parser("ttp", help="Coverage for a TTP")
    p_q_ttp.add_argument("ttp_id")
    _add_db_arg(p_q_ttp)
    p_q_ttp.set_defaults(func=cmd_query_ttp)

    # gaps
    p_gaps = sub.add_parser("gaps", help="Gap analysis")
    g_sub = p_gaps.add_subparsers(dest="gap_type", required=True)

    p_g_det = g_sub.add_parser("detection", help="ThreatInstances with no detection")
    p_g_det.add_argument("--app", metavar="APP_ID", default=None)
    _add_db_arg(p_g_det)
    p_g_det.set_defaults(func=cmd_gaps_detection)

    p_g_mit = g_sub.add_parser("mitigation", help="ThreatInstances with no control")
    p_g_mit.add_argument("--app", metavar="APP_ID", default=None)
    _add_db_arg(p_g_mit)
    p_g_mit.set_defaults(func=cmd_gaps_mitigation)

    p_g_fc = g_sub.add_parser("false-coverage", help="Detections powered by telemetry from a different app")
    p_g_fc.add_argument("--app", metavar="APP_ID", default=None)
    _add_db_arg(p_g_fc)
    p_g_fc.set_defaults(func=cmd_gaps_false_coverage)

    p_g_mr = g_sub.add_parser(
        "mitre-recommendations",
        help="Apps with MITRE-recommended mitigations not covered by any control_instance",
    )
    p_g_mr.add_argument("--app", metavar="APP_ID", default=None)
    p_g_mr.add_argument("--format", choices=("table", "json", "csv"), default="table")
    _add_db_arg(p_g_mr)
    p_g_mr.set_defaults(func=cmd_gaps_mitre_recommendations)

    # sql
    p_sql = sub.add_parser(
        "sql",
        help="Run a raw SQL query against the database",
        description=(
            "Execute arbitrary SQL. Pass the query as an argument or use '-' to read from stdin.\n"
            "Examples:\n"
            "  scg sql \"SELECT * FROM threat_instance\"\n"
            "  scg sql \"SELECT * FROM app\" --format json\n"
            "  echo \"SELECT id FROM detection\" | scg sql -"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_sql.add_argument("sql", metavar="SQL", help="SQL statement, or '-' to read from stdin")
    p_sql.add_argument(
        "--format", choices=["table", "json", "csv"], default="table",
        help="Output format (default: table)",
    )
    _add_db_arg(p_sql)
    p_sql.set_defaults(func=cmd_sql)

    # recompute
    p_rc = sub.add_parser("recompute", help="Recompute materialized coverage fields")
    p_rc.add_argument("--ti", metavar="TI_ID", default=None, help="Limit to one ThreatInstance")
    _add_db_arg(p_rc)
    p_rc.set_defaults(func=cmd_recompute)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
