from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func
from app.models import Report, Vulnerability, Client, User
from app import db

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    total_reports = Report.query.count()
    total_clients = Client.query.count()
    total_vulns = Vulnerability.query.count()
    open_vulns = Vulnerability.query.filter_by(status='Open').count()
    critical_vulns = Vulnerability.query.filter_by(severity='Critical', status='Open').count()
    high_vulns = Vulnerability.query.filter_by(severity='High', status='Open').count()

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

    recent_vulns = (Vulnerability.query
                    .filter_by(status='Open')
                    .order_by(Vulnerability.severity_order.asc(),
                               Vulnerability.created_at.desc())
                    .limit(5).all())

    my_reports = Report.query.filter_by(author_id=current_user.id).count()

    return render_template('dashboard/index.html',
                           total_reports=total_reports,
                           total_clients=total_clients,
                           total_vulns=total_vulns,
                           open_vulns=open_vulns,
                           critical_vulns=critical_vulns,
                           high_vulns=high_vulns,
                           status_labels=status_labels,
                           status_counts=status_counts,
                           sev_labels=sev_labels,
                           sev_counts=sev_counts,
                           recent_reports=recent_reports,
                           recent_vulns=recent_vulns,
                           my_reports=my_reports)
