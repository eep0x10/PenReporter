from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from app import db
from app.models import Product
from app.forms import ProductForm

products_bp = Blueprint('products', __name__, url_prefix='/produtos')


@products_bp.route('/')
@login_required
def index():
    type_filter = request.args.get('type', '')
    q = Product.query
    if type_filter:
        q = q.filter_by(product_type=type_filter)
    products = q.order_by(Product.name).all()
    return render_template('clients/index.html', products=products, type_filter=type_filter)


@products_bp.route('/criar', methods=['GET', 'POST'])
@login_required
def create():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            product_type=form.product_type.data or None,
            platform=form.platform.data or None,
            target_url=form.target_url.data,
            owner=form.owner.data,
            contact_name=form.contact_name.data,
            contact_email=form.contact_email.data,
            contact_phone=form.contact_phone.data,
            description=form.description.data,
        )
        db.session.add(product)
        db.session.commit()
        flash('Produto cadastrado com sucesso!', 'success')
        return redirect(url_for('products.index'))
    return render_template('clients/form.html', form=form, title='Novo Produto')


@products_bp.route('/<int:product_id>/editar', methods=['GET', 'POST'])
@login_required
def edit(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        product.name = form.name.data
        product.product_type = form.product_type.data or None
        product.platform = form.platform.data or None
        product.target_url = form.target_url.data
        product.owner = form.owner.data
        product.contact_name = form.contact_name.data
        product.contact_email = form.contact_email.data
        product.contact_phone = form.contact_phone.data
        product.description = form.description.data
        db.session.commit()
        flash('Produto atualizado!', 'success')
        return redirect(url_for('products.index'))
    return render_template('clients/form.html', form=form, product=product,
                           title='Editar Produto')


@products_bp.route('/<int:product_id>/excluir', methods=['POST'])
@login_required
def delete(product_id):
    product = Product.query.get_or_404(product_id)
    if product.reports.count() > 0:
        flash('Não é possível remover produto com relatórios associados.', 'danger')
        return redirect(url_for('products.index'))
    db.session.delete(product)
    db.session.commit()
    flash('Produto removido.', 'success')
    return redirect(url_for('products.index'))
