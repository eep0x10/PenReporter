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


class ClientForm(FlaskForm):
    name = StringField('Nome da Empresa', validators=[DataRequired(), Length(2, 120)])
    industry = StringField('Setor / Indústria', validators=[Optional(), Length(0, 80)])
    contact_name = StringField('Contato Principal', validators=[Optional(), Length(0, 120)])
    contact_email = EmailField('Email do Contato', validators=[Optional(), Email()])
    contact_phone = StringField('Telefone', validators=[Optional(), Length(0, 30)])
    description = TextAreaField('Descrição', validators=[Optional()])
    submit = SubmitField('Salvar')


class ReportForm(FlaskForm):
    title = StringField('Título do Relatório', validators=[DataRequired(), Length(3, 200)])
    client_id = SelectField('Cliente', coerce=int, validators=[DataRequired()])
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
    proof_of_concept = TextAreaField('Prova de Conceito (PoC)', validators=[Optional()])
    impact = TextAreaField('Impacto', validators=[Optional()])
    recommendation = TextAreaField('Recomendação', validators=[Optional()])
    references = TextAreaField('Referências', validators=[Optional()])
    submit = SubmitField('Salvar')
