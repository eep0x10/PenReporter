from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, abort, Response)
from flask_login import login_required, current_user
from app import db
from app.models import Report, Product, Vulnerability, User
from app.forms import ReportForm

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
@login_required
def index():
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')
    q = Report.query
    if status_filter:
        q = q.filter_by(status=status_filter)
    if type_filter:
        q = q.filter_by(report_type=type_filter)
    reports = q.order_by(Report.updated_at.desc()).all()
    return render_template('reports/index.html', reports=reports,
                           status_filter=status_filter, type_filter=type_filter)


def _populate_report_form(form):
    form.product_id.choices = [(p.id, p.name) for p in Product.query.order_by('name').all()]
    users = User.query.order_by(User.full_name).all()
    form.reviewer_id.choices = [(0, '— Sem revisor —')] + [(u.id, u.full_name) for u in users]


@reports_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ReportForm()
    _populate_report_form(form)
    if not form.product_id.choices:
        flash('Cadastre um produto antes de criar um relatório.', 'warning')
        return redirect(url_for('products.create'))
    if form.validate_on_submit():
        reviewer = form.reviewer_id.data if form.reviewer_id.data and form.reviewer_id.data != 0 else None
        report = Report(
            title=form.title.data,
            product_id=form.product_id.data,
            author_id=current_user.id,
            reviewer_id=reviewer,
            report_type=form.report_type.data,
            status=form.status.data,
            version=form.version.data or '1.0',
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            executive_summary=form.executive_summary.data,
            methodology=form.methodology.data,
            scope=form.scope.data,
            conclusion=form.conclusion.data,
        )
        report.overall_risk = report.get_overall_risk()
        db.session.add(report)
        db.session.commit()
        flash('Relatório criado com sucesso!', 'success')
        return redirect(url_for('reports.view', report_id=report.id))
    return render_template('reports/form.html', form=form, title='Novo Relatório')


@reports_bp.route('/<int:report_id>')
@login_required
def view(report_id):
    report = Report.query.get_or_404(report_id)
    counts = report.get_vuln_counts()
    vulns = report.vulnerabilities.all()
    users = User.query.order_by(User.full_name).all()
    return render_template('reports/view.html', report=report, counts=counts,
                           vulns=vulns, users=users)


@reports_bp.route('/<int:report_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(report_id):
    report = Report.query.get_or_404(report_id)
    form = ReportForm(obj=report)
    _populate_report_form(form)
    if form.validate_on_submit():
        report.title = form.title.data
        report.product_id = form.product_id.data
        report.reviewer_id = form.reviewer_id.data if form.reviewer_id.data and form.reviewer_id.data != 0 else None
        report.report_type = form.report_type.data
        report.status = form.status.data
        report.version = form.version.data or '1.0'
        report.start_date = form.start_date.data
        report.end_date = form.end_date.data
        report.executive_summary = form.executive_summary.data
        report.methodology = form.methodology.data
        report.scope = form.scope.data
        report.conclusion = form.conclusion.data
        report.overall_risk = report.get_overall_risk()
        db.session.commit()
        flash('Relatório atualizado!', 'success')
        return redirect(url_for('reports.view', report_id=report.id))
    return render_template('reports/form.html', form=form, report=report,
                           title='Editar Relatório')


@reports_bp.route('/<int:report_id>/delete', methods=['POST'])
@login_required
def delete(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash('Relatório removido.', 'success')
    return redirect(url_for('reports.index'))


@reports_bp.route('/<int:report_id>/pdf')
@login_required
def generate_pdf(report_id):
    report = Report.query.get_or_404(report_id)
    counts = report.get_vuln_counts()
    vulns = report.vulnerabilities.all()

    try:
        from weasyprint import HTML
        from flask import render_template, request
        html_content = render_template('reports/pdf.html',
                                       report=report, counts=counts, vulns=vulns)
        pdf = HTML(string=html_content, base_url=request.base_url).write_pdf()
        filename = f"report_{report.id}_{report.title[:30].replace(' ', '_')}.pdf"
        return Response(
            pdf,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        flash(f'Erro ao gerar PDF: {str(e)}. Verifique se WeasyPrint está instalado.', 'danger')
        return redirect(url_for('reports.view', report_id=report_id))
