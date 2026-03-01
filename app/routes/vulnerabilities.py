import base64
import os
import re
import uuid

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_required

from app import db
from app.models import Vulnerability, Report, CWE, Evidence
from app.forms import VulnerabilityForm

vulns_bp = Blueprint('vulns', __name__, url_prefix='/vulnerabilities')

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Maps MIME subtype → file extension
_MIME_TO_EXT = {'png': 'png', 'jpeg': 'jpg', 'gif': 'gif', 'webp': 'webp'}


def _allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def _save_evidence_file(file, report_id):
    """Save an uploaded image under static/ev/<report_id>/ and return the relative path."""
    ext = file.filename.rsplit('.', 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    upload_dir = os.path.join(current_app.static_folder, 'ev', str(report_id))
    os.makedirs(upload_dir, exist_ok=True)
    file.save(os.path.join(upload_dir, stored_name))
    return f"{report_id}/{stored_name}"


def _attach_base64_evidences(vuln, b64_list, descriptions, bodies):
    """Decode base64 data-URIs sent by the browser, save to disk, create Evidence records."""
    descriptions = list(descriptions)
    bodies = list(bodies)
    while len(descriptions) < len(b64_list):
        descriptions.append('')
    while len(bodies) < len(b64_list):
        bodies.append('')

    current_count = len(vuln.evidences)
    for i, (b64_str, desc, body) in enumerate(zip(b64_list, descriptions, bodies)):
        b64_str = b64_str.strip()
        if not b64_str:
            continue
        # Expect "data:image/<subtype>;base64,<data>"
        m = re.match(r'data:image/(png|jpeg|gif|webp);base64,(.+)', b64_str, re.DOTALL)
        if not m:
            continue
        subtype, b64_data = m.group(1), m.group(2)
        ext = _MIME_TO_EXT.get(subtype, subtype)
        try:
            img_bytes = base64.b64decode(b64_data)
        except Exception:
            continue

        stored_name = f"{uuid.uuid4().hex}.{ext}"
        upload_dir = os.path.join(
            current_app.static_folder, 'ev', str(vuln.report_id)
        )
        os.makedirs(upload_dir, exist_ok=True)
        with open(os.path.join(upload_dir, stored_name), 'wb') as f:
            f.write(img_bytes)

        ev = Evidence(
            vulnerability_id=vuln.id,
            filename=f"{vuln.report_id}/{stored_name}",
            description=desc.strip() if desc else '',
            body_text=body.strip() if body else None,
            order_index=current_count + i,
        )
        db.session.add(ev)


def _update_existing_evidences(vuln):
    """Update captions and body texts of existing evidences from form data."""
    for ev in vuln.evidences:
        desc_key = f'evidence_desc_{ev.id}'
        body_key = f'evidence_body_{ev.id}'
        if desc_key in request.form:
            ev.description = request.form[desc_key].strip()
        if body_key in request.form:
            ev.body_text = request.form[body_key].strip() or None


def _populate_cwe_choices(form):
    cwes = CWE.query.order_by(CWE.cwe_id).all()
    form.cwe_id.choices = [(0, '— Sem CWE —')] + [(c.id, c.display_name) for c in cwes]


@vulns_bp.route('/')
@login_required
def index():
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')
    cwe_filter = request.args.get('cwe', '')
    q = Vulnerability.query
    if severity_filter:
        q = q.filter_by(severity=severity_filter)
    if status_filter:
        q = q.filter_by(status=status_filter)
    if cwe_filter:
        q = q.filter_by(cwe_id=int(cwe_filter))
    vulns = q.order_by(Vulnerability.severity_order.asc(),
                       Vulnerability.created_at.desc()).all()
    cwes = CWE.query.order_by(CWE.cwe_id).all()
    return render_template('vulnerabilities/index.html', vulns=vulns,
                           severity_filter=severity_filter, status_filter=status_filter,
                           cwe_filter=cwe_filter, cwes=cwes)


@vulns_bp.route('/evidencias/upload', methods=['POST'])
@login_required
def upload_evidence_ajax():
    """AJAX endpoint: upload a single evidence image, return its stored path."""
    file = request.files.get('file')
    report_id = request.form.get('report_id', type=int)

    if not file or not file.filename:
        return jsonify(ok=False, error='Nenhum arquivo enviado'), 400
    if not _allowed_image(file.filename):
        return jsonify(ok=False, error='Tipo de arquivo não permitido (use PNG, JPG, GIF ou WEBP)'), 400
    if not report_id:
        return jsonify(ok=False, error='report_id obrigatório'), 400

    try:
        filename = _save_evidence_file(file, report_id)
        return jsonify(ok=True, filename=filename)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500


@vulns_bp.route('/create', methods=['GET', 'POST'])
@vulns_bp.route('/create/<int:report_id>', methods=['GET', 'POST'])
@login_required
def create(report_id=None):
    form = VulnerabilityForm()
    _populate_cwe_choices(form)
    report = None
    if report_id:
        report = Report.query.get_or_404(report_id)
    if form.validate_on_submit():
        rid = report_id or request.form.get('report_id')
        if not rid:
            flash('Selecione um relatório.', 'danger')
            return redirect(url_for('vulns.create'))
        cwe_id_val = form.cwe_id.data if form.cwe_id.data and form.cwe_id.data != 0 else None
        vuln = Vulnerability(
            report_id=int(rid),
            cwe_id=cwe_id_val,
            title=form.title.data,
            description=form.description.data,
            cvss_score=form.cvss_score.data,
            cvss_vector=form.cvss_vector.data,
            cve_id=form.cve_id.data,
            status=form.status.data,
            affected_component=form.affected_component.data,
            impact=form.impact.data,
            recommendation=form.recommendation.data,
            references=form.references.data,
        )
        vuln.set_severity(form.severity.data)
        db.session.add(vuln)
        db.session.flush()

        _attach_base64_evidences(
            vuln,
            request.form.getlist('evidence_b64[]'),
            request.form.getlist('evidence_descriptions[]'),
            request.form.getlist('evidence_bodies[]'),
        )

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
    _populate_cwe_choices(form)
    if form.validate_on_submit():
        vuln.cwe_id = form.cwe_id.data if form.cwe_id.data and form.cwe_id.data != 0 else None
        vuln.title = form.title.data
        vuln.description = form.description.data
        vuln.cvss_score = form.cvss_score.data
        vuln.cvss_vector = form.cvss_vector.data
        vuln.cve_id = form.cve_id.data
        vuln.status = form.status.data
        vuln.affected_component = form.affected_component.data
        vuln.impact = form.impact.data
        vuln.recommendation = form.recommendation.data
        vuln.references = form.references.data
        vuln.set_severity(form.severity.data)

        _update_existing_evidences(vuln)
        _attach_base64_evidences(
            vuln,
            request.form.getlist('evidence_b64[]'),
            request.form.getlist('evidence_descriptions[]'),
            request.form.getlist('evidence_bodies[]'),
        )

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
    for ev in vuln.evidences:
        _delete_evidence_file(ev.filename)
    db.session.delete(vuln)
    db.session.commit()
    flash('Vulnerabilidade removida.', 'success')
    return redirect(url_for('reports.view', report_id=report_id))


@vulns_bp.route('/evidencias/<int:ev_id>/excluir', methods=['POST'])
@login_required
def delete_evidence(ev_id):
    ev = Evidence.query.get_or_404(ev_id)
    vuln_id = ev.vulnerability_id
    _delete_evidence_file(ev.filename)
    db.session.delete(ev)
    db.session.commit()
    flash('Evidência excluída.', 'success')
    return redirect(url_for('vulns.edit', vuln_id=vuln_id))


def _delete_evidence_file(filename):
    try:
        path = os.path.join(current_app.static_folder, 'ev', filename)
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
