import os
from app import create_app, db
from app.models import User, Client, Report, Vulnerability

app = create_app(os.environ.get('FLASK_ENV', 'default'))


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Client=Client, Report=Report,
                Vulnerability=Vulnerability)


@app.cli.command('init-db')
def init_db():
    """Create all database tables."""
    with app.app_context():
        db.create_all()
        print('Database tables created.')


@app.cli.command('create-admin')
def create_admin():
    """Create default admin user."""
    with app.app_context():
        if User.query.filter_by(username='admin').first():
            print('Admin user already exists.')
            return
        user = User(
            username='admin',
            email='admin@pentreport.local',
            full_name='Administrador',
            role='admin',
        )
        user.set_password('admin123')
        db.session.add(user)
        db.session.commit()
        print('Admin created — user: admin | pass: admin123')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
