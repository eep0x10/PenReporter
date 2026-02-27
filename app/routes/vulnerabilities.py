from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from app import db
from app.models import Vulnerability, Report
from app.forms import VulnerabilityForm

vulns_bp = Blueprint('vulns', __name__, url_prefix='/vulnerabilities')


@vulns_bp.route('/')
@login_required
def index():
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')
    q = Vulnerability.query
    if severity_filter:
        q = q.filter_by(severity=severity_filter)
    if status_filter:
        q = q.filter_by(status=status_filter)
    vulns = q.order_by(Vulnerability.severity_order.asc(),
                       Vulnerability.created_at.desc()).all()
    return render_template('vulnerabilities/index.html', vulns=vulns,
                           severity_filter=severity_filter, status_filter=status_filter)


@vulns_bp.route('/create', methods=['GET', 'POST'])
@vulns_bp.route('/create/<int:report_id>', methods=['GET', 'POST'])
@login_required
def create(report_id=None):
    form = VulnerabilityForm()
    report = None
    if report_id:
        report = Report.query.get_or_404(report_id)
    if form.validate_on_submit():
        rid = report_id or request.form.get('report_id')
        if not rid:
            flash('Selecione um relatório.', 'danger')
            return redirect(url_for('vulns.create'))
        vuln = Vulnerability(
            report_id=int(rid),
            title=form.title.data,
            description=form.description.data,
            cvss_score=form.cvss_score.data,
            cvss_vector=form.cvss_vector.data,
            cve_id=form.cve_id.data,
            status=form.status.data,
            affected_component=form.affected_component.data,
            proof_of_concept=form.proof_of_concept.data,
            impact=form.impact.data,
            recommendation=form.recommendation.data,
            references=form.references.data,
        )
        vuln.set_severity(form.severity.data)
        db.session.add(vuln)
        # Update report overall risk
        rep = Report.query.get(int(rid))
        if rep:
            db.session.flush()
            rep.overall_risk = rep.get_overall_risk()
        db.session.commit()
        flash('Vulnerabilidade adicionada!', 'success')
        if report_id:
            return redirect(url_for('reports.view', report_id=report_id))
        return redirect(url_for('vulns.index'))
    reports = Report.query.order_by(Report.title).all()
    return render_template('vulnerabilities/form.html', form=form, report=report,
                           reports=reports, title='Nova Vulnerabilidade')


@vulns_bp.route('/<int:vuln_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    form = VulnerabilityForm(obj=vuln)
    if form.validate_on_submit():
        vuln.title = form.title.data
        vuln.description = form.description.data
        vuln.cvss_score = form.cvss_score.data
        vuln.cvss_vector = form.cvss_vector.data
        vuln.cve_id = form.cve_id.data
        vuln.status = form.status.data
        vuln.affected_component = form.affected_component.data
        vuln.proof_of_concept = form.proof_of_concept.data
        vuln.impact = form.impact.data
        vuln.recommendation = form.recommendation.data
        vuln.references = form.references.data
        vuln.set_severity(form.severity.data)
        report = Report.query.get(vuln.report_id)
        if report:
            db.session.flush()
            report.overall_risk = report.get_overall_risk()
        db.session.commit()
        flash('Vulnerabilidade atualizada!', 'success')
        return redirect(url_for('reports.view', report_id=vuln.report_id))
    reports = Report.query.order_by(Report.title).all()
    return render_template('vulnerabilities/form.html', form=form, vuln=vuln,
                           reports=reports, title='Editar Vulnerabilidade')


@vulns_bp.route('/<int:vuln_id>/delete', methods=['POST'])
@login_required
def delete(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    report_id = vuln.report_id
    db.session.delete(vuln)
    db.session.commit()
    flash('Vulnerabilidade removida.', 'success')
    return redirect(url_for('reports.view', report_id=report_id))
