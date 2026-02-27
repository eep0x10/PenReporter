from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from app import db
from app.models import Client
from app.forms import ClientForm

clients_bp = Blueprint('clients', __name__, url_prefix='/clients')


@clients_bp.route('/')
@login_required
def index():
    clients = Client.query.order_by(Client.name).all()
    return render_template('clients/index.html', clients=clients)


@clients_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ClientForm()
    if form.validate_on_submit():
        client = Client(
            name=form.name.data,
            industry=form.industry.data,
            contact_name=form.contact_name.data,
            contact_email=form.contact_email.data,
            contact_phone=form.contact_phone.data,
            description=form.description.data,
        )
        db.session.add(client)
        db.session.commit()
        flash('Cliente cadastrado com sucesso!', 'success')
        return redirect(url_for('clients.index'))
    return render_template('clients/form.html', form=form, title='Novo Cliente')


@clients_bp.route('/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(client_id):
    client = Client.query.get_or_404(client_id)
    form = ClientForm(obj=client)
    if form.validate_on_submit():
        client.name = form.name.data
        client.industry = form.industry.data
        client.contact_name = form.contact_name.data
        client.contact_email = form.contact_email.data
        client.contact_phone = form.contact_phone.data
        client.description = form.description.data
        db.session.commit()
        flash('Cliente atualizado!', 'success')
        return redirect(url_for('clients.index'))
    return render_template('clients/form.html', form=form, client=client,
                           title='Editar Cliente')


@clients_bp.route('/<int:client_id>/delete', methods=['POST'])
@login_required
def delete(client_id):
    client = Client.query.get_or_404(client_id)
    if client.reports.count() > 0:
        flash('Não é possível remover cliente com relatórios associados.', 'danger')
        return redirect(url_for('clients.index'))
    db.session.delete(client)
    db.session.commit()
    flash('Cliente removido.', 'success')
    return redirect(url_for('clients.index'))
