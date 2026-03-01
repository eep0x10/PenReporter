import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_USER = os.environ.get('DB_USER', 'pentreport')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'pentreport123')
    DB_NAME = os.environ.get('DB_NAME', 'pentreport')
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 299,
        'pool_pre_ping': True,
    }
    WTF_CSRF_ENABLED = True
    # Permite formulários com imagens base64 grandes (múltiplas evidências)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024      # 50 MB – total do body
    MAX_FORM_MEMORY_SIZE = 50 * 1024 * 1024    # 50 MB – campos de texto (base64)


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
