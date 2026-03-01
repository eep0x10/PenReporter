from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from sqlalchemy import func
from app import db
from app.models import CWE, Vulnerability
from app.forms import CWEForm

cwes_bp = Blueprint('cwes', __name__, url_prefix='/cwes')


@cwes_bp.route('/')
@login_required
def index():
    search = request.args.get('q', '')
    q = CWE.query
    if search:
        q = q.filter(
            db.or_(CWE.cwe_id.ilike(f'%{search}%'), CWE.name.ilike(f'%{search}%'))
        )
    cwes = q.order_by(CWE.cwe_id).all()

    # Count vulnerabilities per CWE
    counts = dict(
        db.session.query(Vulnerability.cwe_id, func.count(Vulnerability.id))
        .filter(Vulnerability.cwe_id.isnot(None))
        .group_by(Vulnerability.cwe_id)
        .all()
    )
    return render_template('cwes/index.html', cwes=cwes, counts=counts, search=search)


@cwes_bp.route('/criar', methods=['GET', 'POST'])
@login_required
def create():
    form = CWEForm()
    if form.validate_on_submit():
        cwe_id_norm = form.cwe_id.data.upper().strip()
        if not cwe_id_norm.startswith('CWE-'):
            cwe_id_norm = 'CWE-' + cwe_id_norm.lstrip('CWE-').lstrip('-')
        existing = CWE.query.filter_by(cwe_id=cwe_id_norm).first()
        if existing:
            flash(f'{cwe_id_norm} já está cadastrado.', 'warning')
            return redirect(url_for('cwes.index'))
        cwe = CWE(cwe_id=cwe_id_norm, name=form.name.data, description=form.description.data)
        db.session.add(cwe)
        db.session.commit()
        flash(f'{cwe_id_norm} cadastrado com sucesso!', 'success')
        return redirect(url_for('cwes.index'))
    return render_template('cwes/form.html', form=form, title='Nova CWE')


@cwes_bp.route('/<int:cwe_pk>/editar', methods=['GET', 'POST'])
@login_required
def edit(cwe_pk):
    cwe = CWE.query.get_or_404(cwe_pk)
    form = CWEForm(obj=cwe)
    if form.validate_on_submit():
        cwe_id_norm = form.cwe_id.data.upper().strip()
        if not cwe_id_norm.startswith('CWE-'):
            cwe_id_norm = 'CWE-' + cwe_id_norm.lstrip('CWE-').lstrip('-')
        existing = CWE.query.filter(CWE.cwe_id == cwe_id_norm, CWE.id != cwe.id).first()
        if existing:
            flash(f'{cwe_id_norm} já está cadastrado.', 'warning')
        else:
            cwe.cwe_id = cwe_id_norm
            cwe.name = form.name.data
            cwe.description = form.description.data
            db.session.commit()
            flash('CWE atualizada!', 'success')
            return redirect(url_for('cwes.index'))
    return render_template('cwes/form.html', form=form, cwe=cwe, title='Editar CWE')


@cwes_bp.route('/<int:cwe_pk>/excluir', methods=['POST'])
@login_required
def delete(cwe_pk):
    cwe = CWE.query.get_or_404(cwe_pk)
    if cwe.vulnerabilities.count() > 0:
        flash('Não é possível remover CWE com vulnerabilidades associadas.', 'danger')
        return redirect(url_for('cwes.index'))
    db.session.delete(cwe)
    db.session.commit()
    flash('CWE removida.', 'success')
    return redirect(url_for('cwes.index'))
