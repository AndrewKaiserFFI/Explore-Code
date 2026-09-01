"""
Report views: dashboard, detailed drift lists (by category), remediation
plan (grouped by outage requirement), breaking changes, remediation history.
All routes require login.
"""

import os
from flask import Blueprint, render_template, request, redirect, url_for, flash

from db import db_session
from auth.decorators import login_required, admin_required
from models import Snapshot, DriftFinding, EnvironmentRole, FindingStatus, Category
from reports.ingestion import capture_baseline_live, sync_measured_exports_from_git, get_latest_snapshot

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _latest_pair():
    baseline = get_latest_snapshot(db_session, EnvironmentRole.BASELINE)
    measured = get_latest_snapshot(db_session, EnvironmentRole.MEASURED)
    return baseline, measured


def _current_findings_query():
    baseline, measured = _latest_pair()
    if not baseline or not measured:
        return None, None, None
    query = db_session.query(DriftFinding).filter(
        DriftFinding.baseline_snapshot_id == baseline.id,
        DriftFinding.measured_snapshot_id == measured.id,
    )
    return query, baseline, measured


@reports_bp.route("/")
@login_required
def dashboard():
    baseline, measured = _latest_pair()

    version_alert = None
    if baseline and measured:
        b_vc = baseline.raw_config.get("vcenter", {}).get("version")
        m_vc = measured.raw_config.get("vcenter", {}).get("version")
        if b_vc and m_vc and b_vc != m_vc:
            version_alert = f"vCenter version mismatch: baseline={b_vc}, measured={m_vc}"

    query, _, _ = _current_findings_query()
    summary = {"total": 0, "breaking": 0, "requires_outage": 0, "open": 0}
    if query is not None:
        all_findings = query.all()
        summary["total"] = len(all_findings)
        summary["breaking"] = sum(1 for f in all_findings if f.is_breaking_change)
        summary["requires_outage"] = sum(1 for f in all_findings if f.requires_outage)
        summary["open"] = sum(1 for f in all_findings if f.status == FindingStatus.OPEN)

    return render_template(
        "reports/dashboard.html",
        baseline=baseline,
        measured=measured,
        version_alert=version_alert,
        summary=summary,
    )


@reports_bp.route("/capture-baseline", methods=["POST"])
@admin_required
def capture_baseline():
    environment_name = os.environ.get("BASELINE_ENVIRONMENT_NAME", "baseline")
    try:
        capture_baseline_live(db_session, environment_name)
        flash("Baseline captured and compared successfully.", "success")
    except Exception as exc:
        flash(f"Failed to capture baseline: {exc}", "danger")
    return redirect(url_for("reports.dashboard"))


@reports_bp.route("/sync-measured", methods=["POST"])
@admin_required
def sync_measured():
    environment_name = os.environ.get("MEASURED_ENVIRONMENT_NAME", "measured")
    try:
        new_snapshots = sync_measured_exports_from_git(db_session, environment_name)
        flash(f"Synced {len(new_snapshots)} new measured snapshot(s) from Git.", "success")
    except Exception as exc:
        flash(f"Failed to sync measured exports: {exc}", "danger")
    return redirect(url_for("reports.dashboard"))


@reports_bp.route("/drift")
@login_required
def drift_list():
    query, baseline, measured = _current_findings_query()
    category_filter = request.args.get("category")

    findings = []
    if query is not None:
        if category_filter:
            query = query.filter(DriftFinding.category == category_filter)
        findings = query.order_by(DriftFinding.category, DriftFinding.setting_key).all()

    return render_template(
        "reports/drift_list.html",
        findings=findings,
        baseline=baseline,
        measured=measured,
        categories=[c.value for c in Category],
        selected_category=category_filter,
    )


@reports_bp.route("/remediation-plan")
@login_required
def remediation_plan():
    query, baseline, measured = _current_findings_query()

    outage_required = []
    live_remediable = []
    if query is not None:
        open_findings = query.filter(DriftFinding.status == FindingStatus.OPEN).all()
        outage_required = [f for f in open_findings if f.requires_outage]
        live_remediable = [f for f in open_findings if not f.requires_outage]

    return render_template(
        "reports/remediation_plan.html",
        outage_required=outage_required,
        live_remediable=live_remediable,
        baseline=baseline,
        measured=measured,
    )


@reports_bp.route("/breaking-changes")
@login_required
def breaking_changes():
    query, baseline, measured = _current_findings_query()

    findings = []
    if query is not None:
        findings = (
            query.filter(
                DriftFinding.is_breaking_change == True,  # noqa: E712
                DriftFinding.status == FindingStatus.OPEN,
            )
            .order_by(DriftFinding.impacts_management_network.desc(), DriftFinding.category)
            .all()
        )

    return render_template(
        "reports/breaking_changes.html",
        findings=findings,
        baseline=baseline,
        measured=measured,
    )


@reports_bp.route("/remediation-history")
@login_required
def remediation_history():
    baseline = get_latest_snapshot(db_session, EnvironmentRole.BASELINE)

    findings = []
    if baseline:
        findings = (
            db_session.query(DriftFinding)
            .filter(DriftFinding.baseline_snapshot_id == baseline.id)
            .order_by(DriftFinding.first_detected_at.desc())
            .all()
        )

    return render_template(
        "reports/remediation_history.html",
        findings=findings,
        baseline=baseline,
    )
