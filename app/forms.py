from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, TextAreaField, SelectField,
                     FloatField, DateField, SubmitField, EmailField)
from wtforms.validators import DataRequired, Length, Email, Optional, NumberRange, EqualTo


class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')


class RegisterForm(FlaskForm):
    full_name = StringField('Nome Completo', validators=[DataRequired(), Length(2, 120)])
    username = StringField('Usuário', validators=[DataRequired(), Length(3, 64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(8, 128)])
    confirm_password = PasswordField('Confirmar Senha',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Criar Conta')


class CWEForm(FlaskForm):
    cwe_id = StringField('CWE ID', validators=[DataRequired(), Length(3, 20)],
                         description='Ex: CWE-79, CWE-89, CWE-22')
    name = StringField('Nome', validators=[DataRequired(), Length(3, 200)])
    description = TextAreaField('Descrição', validators=[Optional()])
    submit = SubmitField('Salvar')


class ProductForm(FlaskForm):
    name = StringField('Nome do Produto / Alvo', validators=[DataRequired(), Length(2, 120)])
    product_type = SelectField('Tipo de Produto', choices=[
        ('', '— Selecione —'),
        ('Web Application', 'Web Application'),
        ('Mobile App', 'Mobile App'),
        ('API', 'API / Web Service'),
        ('Network/Infrastructure', 'Network / Infraestrutura'),
        ('Cloud', 'Cloud'),
        ('Desktop', 'Desktop Application'),
        ('Embedded', 'Embedded / IoT'),
        ('Physical', 'Physical'),
        ('Other', 'Outro'),
    ], validators=[Optional()])
    platform = SelectField('Plataforma', choices=[
        ('', '— Selecione —'),
        ('Web', 'Web'),
        ('iOS', 'iOS'),
        ('Android', 'Android'),
        ('Windows', 'Windows'),
        ('Linux', 'Linux'),
        ('macOS', 'macOS'),
        ('Internal Network', 'Rede Interna'),
        ('AWS', 'AWS'),
        ('Azure', 'Azure'),
        ('GCP', 'GCP'),
        ('Other', 'Outro'),
    ], validators=[Optional()])
    target_url = StringField('URL / Hostname / IP / Escopo',
                             validators=[Optional(), Length(0, 300)],
                             description='Ex: https://app.empresa.com, 192.168.1.0/24')
    owner = StringField('Empresa / Organização Proprietária',
                        validators=[Optional(), Length(0, 120)])
    contact_name = StringField('Contato Principal', validators=[Optional(), Length(0, 120)])
    contact_email = EmailField('Email do Contato', validators=[Optional(), Email()])
    contact_phone = StringField('Telefone', validators=[Optional(), Length(0, 30)])
    description = TextAreaField('Notas / Descrição', validators=[Optional()])
    submit = SubmitField('Salvar')


class ReportForm(FlaskForm):
    title = StringField('Título do Relatório', validators=[DataRequired(), Length(3, 200)])
    product_id = SelectField('Produto / Alvo', coerce=int, validators=[DataRequired()])
    report_type = SelectField('Tipo de Teste', choices=[
        ('Web Application', 'Web Application'),
        ('Network', 'Network / Infraestrutura'),
        ('Mobile', 'Mobile'),
        ('Social Engineering', 'Social Engineering'),
        ('Physical', 'Physical'),
        ('Red Team', 'Red Team'),
        ('Cloud', 'Cloud'),
        ('API', 'API'),
    ])
    status = SelectField('Status', choices=[
        ('Draft', 'Rascunho'),
        ('In Review', 'Em Revisão'),
        ('Final', 'Final'),
    ])
    reviewer_id = SelectField('Revisor', coerce=int, validators=[Optional()])
    version = StringField('Versão', validators=[Optional(), Length(0, 10)], default='1.0')
    start_date = DateField('Data de Início', validators=[Optional()])
    end_date = DateField('Data de Fim', validators=[Optional()])
    executive_summary = TextAreaField('Resumo Executivo', validators=[Optional()])
    methodology = TextAreaField('Metodologia', validators=[Optional()])
    scope = TextAreaField('Escopo', validators=[Optional()])
    conclusion = TextAreaField('Conclusão', validators=[Optional()])
    submit = SubmitField('Salvar')


class VulnerabilityForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired(), Length(3, 200)])
    cwe_id = SelectField('CWE', coerce=int, validators=[Optional()])
    severity = SelectField('Severidade', choices=[
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Informational', 'Informational'),
    ])
    status = SelectField('Status', choices=[
        ('Open', 'Open'),
        ('Remediated', 'Remediated'),
        ('Accepted Risk', 'Accepted Risk'),
        ('False Positive', 'False Positive'),
    ])
    cvss_score = FloatField('CVSS Score', validators=[Optional(), NumberRange(0.0, 10.0)])
    cvss_vector = StringField('CVSS Vector', validators=[Optional(), Length(0, 200)])
    cve_id = StringField('CVE ID', validators=[Optional(), Length(0, 30)])
    affected_component = StringField('Componente Afetado', validators=[Optional(), Length(0, 200)])
    description = TextAreaField('Descrição', validators=[Optional()])
    impact = TextAreaField('Impacto', validators=[Optional()])
    recommendation = TextAreaField('Recomendação', validators=[Optional()])
    references = TextAreaField('Referências', validators=[Optional()])
    submit = SubmitField('Salvar')
