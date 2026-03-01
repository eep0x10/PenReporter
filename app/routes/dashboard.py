from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func
from app.models import Report, Vulnerability, Product, User, CWE
from app import db

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    total_reports = Report.query.count()
    total_products = Product.query.count()
    total_vulns = Vulnerability.query.count()
    total_cwes = CWE.query.count()

    reports_by_status = db.session.query(
        Report.status, func.count(Report.id)
    ).group_by(Report.status).all()
    status_labels = [r[0] for r in reports_by_status]
    status_counts = [r[1] for r in reports_by_status]

    vulns_by_severity = db.session.query(
        Vulnerability.severity, func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    sev_dict = dict(vulns_by_severity)
    sev_labels = [s for s in severity_order if s in sev_dict]
    sev_counts = [sev_dict[s] for s in sev_labels]

    recent_reports = (Report.query
                      .order_by(Report.created_at.desc())
                      .limit(5).all())

    # Top 10 CWEs by number of vulnerabilities
    top_cwes = (
        db.session.query(CWE, func.count(Vulnerability.id).label('vuln_count'))
        .join(Vulnerability, Vulnerability.cwe_id == CWE.id)
        .group_by(CWE.id)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
        .all()
    )

    # CWE occurrences for chart (all CWEs with at least 1 vuln)
    cwe_chart_data = [
        {'label': c.cwe_id, 'name': c.name, 'count': cnt}
        for c, cnt in top_cwes
    ]

    my_reports = Report.query.filter_by(author_id=current_user.id).count()

    return render_template('dashboard/index.html',
                           total_reports=total_reports,
                           total_products=total_products,
                           total_vulns=total_vulns,
                           total_cwes=total_cwes,
                           status_labels=status_labels,
                           status_counts=status_counts,
                           sev_labels=sev_labels,
                           sev_counts=sev_counts,
                           recent_reports=recent_reports,
                           top_cwes=top_cwes,
                           cwe_chart_data=cwe_chart_data,
                           my_reports=my_reports)
