from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='pentester')  # admin, pentester
    avatar_initials = db.Column(db.String(4))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    reports = db.relationship('Report', backref='author', lazy='dynamic',
                              foreign_keys='Report.author_id')
    reviews = db.relationship('Report', backref='reviewer', lazy='dynamic',
                              foreign_keys='Report.reviewer_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_initials(self):
        parts = self.full_name.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[-1][0]).upper()
        return self.full_name[:2].upper()

    def __repr__(self):
        return f'<User {self.username}>'


class CWE(db.Model):
    __tablename__ = 'cwes'

    id = db.Column(db.Integer, primary_key=True)
    cwe_id = db.Column(db.String(20), unique=True, nullable=False)  # e.g., CWE-79
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    vulnerabilities = db.relationship('Vulnerability', backref='cwe', lazy='dynamic')

    @property
    def display_name(self):
        return f'{self.cwe_id} — {self.name}'

    def __repr__(self):
        return f'<CWE {self.cwe_id}>'


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)          # product name (e.g., "App Bradesco Saúde")
    product_type = db.Column(db.String(50))                   # Web Application, Mobile App, API, etc.
    platform = db.Column(db.String(50))                       # iOS, Android, Web, Linux, etc.
    target_url = db.Column(db.String(300))                    # URL, hostname, IP or scope description
    owner = db.Column(db.String(120))                         # company/org that owns the product
    contact_name = db.Column(db.String(120))
    contact_email = db.Column(db.String(120))
    contact_phone = db.Column(db.String(30))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    reports = db.relationship('Report', backref='product', lazy='dynamic')

    def __repr__(self):
        return f'<Product {self.name}>'


SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}

SEVERITY_COLORS = {
    'Critical': '#f85149',
    'High': '#db6d28',
    'Medium': '#d29922',
    'Low': '#58a6ff',
    'Informational': '#8b949e',
}


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='Draft')  # Draft, In Review, Final
    report_type = db.Column(db.String(50), default='Web Application')
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    executive_summary = db.Column(db.Text)
    methodology = db.Column(db.Text)
    scope = db.Column(db.Text)
    conclusion = db.Column(db.Text)
    overall_risk = db.Column(db.String(20))  # Critical, High, Medium, Low
    version = db.Column(db.String(10), default='1.0')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulnerabilities = db.relationship('Vulnerability', backref='report', lazy='dynamic',
                                      cascade='all, delete-orphan',
                                      order_by='Vulnerability.severity_order')

    def get_vuln_counts(self):
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for v in self.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def get_overall_risk(self):
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if self.vulnerabilities.filter_by(severity=sev).first():
                return sev
        return 'Informational'

    def __repr__(self):
        return f'<Report {self.title}>'


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=False)
    cwe_id = db.Column(db.Integer, db.ForeignKey('cwes.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='Medium')  # Critical, High, Medium, Low, Informational
    severity_order = db.Column(db.Integer, default=2)
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(200))
    cve_id = db.Column(db.String(30))
    status = db.Column(db.String(30), default='Open')  # Open, Remediated, Accepted Risk, False Positive
    affected_component = db.Column(db.String(200))
    proof_of_concept = db.Column(db.Text)
    impact = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    references = db.Column(db.Text)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    evidences = db.relationship('Evidence', backref='vulnerability',
                                cascade='all, delete-orphan',
                                order_by='Evidence.order_index')

    def set_severity(self, severity):
        self.severity = severity
        self.severity_order = SEVERITY_ORDER.get(severity, 4)

    @property
    def severity_color(self):
        return SEVERITY_COLORS.get(self.severity, '#8b949e')

    def __repr__(self):
        return f'<Vulnerability {self.title}>'


class Evidence(db.Model):
    __tablename__ = 'evidences'

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)   # stored under static/ev/
    description = db.Column(db.String(500), nullable=False, default='')  # caption: "Imagem N — description"
    body_text = db.Column(db.Text)                         # optional text shown after the image
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Evidence {self.filename}>'
