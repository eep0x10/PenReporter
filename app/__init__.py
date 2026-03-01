from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from config import config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()


def create_app(config_name='default'):
    import base64, mimetypes, os

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    @app.template_filter('file_to_b64')
    def file_to_b64(filename):
        """Return a base64 data-URI for an evidence image (used in PDF generation)."""
        path = os.path.join(app.static_folder, 'ev', filename)
        try:
            with open(path, 'rb') as f:
                data = base64.b64encode(f.read()).decode()
            mime = mimetypes.guess_type(filename)[0] or 'image/png'
            return f'data:{mime};base64,{data}'
        except Exception:
            return ''

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Faça login para acessar esta página.'
    login_manager.login_message_category = 'warning'

    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.reports import reports_bp
    from app.routes.vulnerabilities import vulns_bp
    from app.routes.clients import products_bp
    from app.routes.cwes import cwes_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(vulns_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(cwes_bp)

    return app
