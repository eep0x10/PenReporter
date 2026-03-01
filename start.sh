#!/usr/bin/env bash
set -e

# ═══════════════════════════════════════════════════════════
#  PentReport — Setup & Start Script
# ═══════════════════════════════════════════════════════════

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗███╗   ██╗████████╗██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗"
  echo "  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝"
  echo "  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║   "
  echo "  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   "
  echo "  ██║     ███████╗██║ ╚████║   ██║   ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║   "
  echo "  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
  echo -e "${RESET}"
  echo -e "  ${CYAN}Pentester Reporting Platform${RESET}"
  echo ""
}

info()    { echo -e "  ${CYAN}[•]${RESET} $1"; }
success() { echo -e "  ${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "  ${RED}[✗]${RESET} $1"; }
step()    { echo -e "\n  ${BOLD}${CYAN}━━ $1 ━━${RESET}"; }

# ── Detect project dir ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

banner

# ═══════════════════════════════════════════════════════════
step "Verificando dependências do sistema"
# ═══════════════════════════════════════════════════════════

# Check Python
if ! command -v python3 &>/dev/null; then
  error "Python 3 não encontrado. Instale com: sudo apt install python3"
  exit 1
fi
PYTHON_VER=$(python3 --version)
success "Python: $PYTHON_VER"

# Check pip
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null; then
  warn "pip não encontrado. Instalando..."
  sudo apt-get install -y python3-pip 2>/dev/null || true
fi
success "pip disponível"

# Check MariaDB / MySQL client
if ! command -v mysql &>/dev/null; then
  warn "MariaDB client não encontrado."
  warn "Para instalar: sudo apt install mariadb-client"
fi

# WeasyPrint system dependencies (optional but needed for PDF)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  info "Verificando dependências do WeasyPrint (PDF)..."
  MISSING_LIBS=()
  for lib in libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2; do
    if ! dpkg -l "$lib" &>/dev/null 2>&1; then
      MISSING_LIBS+=("$lib")
    fi
  done
  if [ ${#MISSING_LIBS[@]} -gt 0 ]; then
    warn "Bibliotecas do sistema para PDF ausentes: ${MISSING_LIBS[*]}"
    warn "Instalando automaticamente (requer sudo)..."
    if sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 \
         libgdk-pixbuf2.0-0 libcairo2 libffi-dev \
         fonts-liberation 2>/dev/null; then
      success "Dependências do sistema instaladas"
    else
      warn "Falha ao instalar dependências do sistema. PDF pode não funcionar."
    fi
  else
    success "Dependências do WeasyPrint OK"
  fi
fi

# ═══════════════════════════════════════════════════════════
step "Configurando ambiente virtual Python"
# ═══════════════════════════════════════════════════════════

if [ ! -d ".venv" ]; then
  info "Criando virtualenv..."
  python3 -m venv .venv
  success "Virtualenv criado em .venv/"
else
  success "Virtualenv já existe"
fi

# Activate venv
source .venv/bin/activate
success "Virtualenv ativado"
# ═══════════════════════════════════════════════════════════
step "Instalando dependências Python"
# ═══════════════════════════════════════════════════════════

pip install --upgrade pip -q

# Install core dependencies (excluding weasyprint line)
info "Instalando dependências principais..."
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Flask-Migrate \
    PyMySQL cryptography WTForms Werkzeug python-dotenv email-validator -q
success "Dependências principais instaladas"

# Try to install weasyprint (may fail without system libs)
info "Tentando instalar WeasyPrint (geração de PDF)..."
if pip install weasyprint -q 2>/dev/null; then
  success "WeasyPrint instalado - geração de PDF disponível"
else
  warn "WeasyPrint não instalado - geração de PDF indisponível"
  warn "Para habilitar PDF: sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libcairo2"
  warn "                    então execute: pip install weasyprint"
fi

# ═══════════════════════════════════════════════════════════
step "Configurando variáveis de ambiente"
# ═══════════════════════════════════════════════════════════

if [ ! -f ".env" ]; then
  info "Arquivo .env não encontrado. Criando a partir do exemplo..."
  cp .env.example .env

  # Generate a secure random key
  if command -v openssl &>/dev/null; then
    SECRET=$(openssl rand -hex 32)
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' "s/change-this-to-a-very-secure-random-key/$SECRET/" .env
    else
      sed -i "s/change-this-to-a-very-secure-random-key/$SECRET/" .env
    fi
    success "SECRET_KEY gerado automaticamente"
  fi

  echo ""
  warn "ATENÇÃO: Edite o arquivo .env com as credenciais do seu banco de dados!"
  echo ""
  echo -e "  ${YELLOW}Configurações padrão:${RESET}"
  echo -e "  ${CYAN}DB_HOST${RESET}     = localhost"
  echo -e "  ${CYAN}DB_USER${RESET}     = pentreport"
  echo -e "  ${CYAN}DB_PASSWORD${RESET} = pentreport123"
  echo -e "  ${CYAN}DB_NAME${RESET}     = pentreport"
  echo ""
  echo -e "  ${YELLOW}Pressione ENTER para continuar com as configurações padrão"
  echo -e "  ou Ctrl+C para editar o .env antes de continuar...${RESET}"
  read -r
else
  success ".env já existe"
fi

# Load env vars
export $(grep -v '^#' .env | xargs) 2>/dev/null || true

# ═══════════════════════════════════════════════════════════
step "Configurando banco de dados MariaDB"
# ═══════════════════════════════════════════════════════════

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-pentreport}"
DB_PASSWORD="${DB_PASSWORD:-pentreport123}"
DB_NAME="${DB_NAME:-pentreport}"

info "Tentando criar banco de dados e usuário..."

# Try to create DB with root (may ask for password)
if command -v mysql &>/dev/null; then
  cat > /tmp/pentreport_setup.sql << EOSQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOSQL

  echo ""
  warn "Tentando criar banco com usuário root do MariaDB/MySQL."
  warn "Se solicitado, insira a senha de root do banco de dados."
  warn "Pressione Ctrl+C e execute manualmente se preferir."
  echo ""

  if mysql -u root -p"${MYSQL_ROOT_PASSWORD:-}" < /tmp/pentreport_setup.sql 2>/dev/null; then
    success "Banco de dados e usuário criados com sucesso"
  elif mysql -u root < /tmp/pentreport_setup.sql 2>/dev/null; then
    success "Banco de dados e usuário criados (sem senha root)"
  else
    warn "Não foi possível criar DB automaticamente."
    warn "Execute manualmente no MariaDB/MySQL:"
    echo ""
    cat /tmp/pentreport_setup.sql
    echo ""
    warn "Depois pressione ENTER para continuar..."
    read -r
  fi
  rm -f /tmp/pentreport_setup.sql
else
  warn "mysql client não encontrado. Certifique-se de criar o banco manualmente."
fi

# ═══════════════════════════════════════════════════════════
step "Criando tabelas do banco de dados"
# ═══════════════════════════════════════════════════════════

# Test DB connection first
info "Testando conexão com o banco de dados..."
python3 -c "
import os, sys
os.environ.setdefault('FLASK_ENV', 'development')
try:
    from app import create_app, db
    app = create_app()
    with app.app_context():
        db.engine.connect()
    print('  OK')
except Exception as e:
    print(f'  ERRO: {e}')
    sys.exit(1)
"

info "Criando tabelas..."
FLASK_APP=run.py flask init-db 2>/dev/null || python3 -c "
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print('  Tabelas criadas.')
"
success "Tabelas criadas"

# ═══════════════════════════════════════════════════════════
step "Criando usuário administrador"
# ═══════════════════════════════════════════════════════════

FLASK_APP=run.py flask create-admin 2>/dev/null || python3 -c "
from app import create_app, db
from app.models import User
app = create_app()
with app.app_context():
    if not User.query.filter_by(username='admin').first():
        u = User(username='admin', email='admin@pentreport.local',
                 full_name='Administrador', role='admin')
        u.set_password('admin123')
        db.session.add(u)
        db.session.commit()
        print('  Admin criado.')
    else:
        print('  Admin já existe.')
"
success "Usuário admin configurado"

# ═══════════════════════════════════════════════════════════
step "Iniciando aplicação"
# ═══════════════════════════════════════════════════════════

PORT="${FLASK_PORT:-5000}"

echo ""
echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "  ${GREEN}${BOLD}║   PentReport iniciado com sucesso!   ║${RESET}"
echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}URL:${RESET}      http://localhost:${PORT}"
echo -e "  ${CYAN}Usuário:${RESET}  admin"
echo -e "  ${CYAN}Senha:${RESET}    admin123"
echo ""
echo -e "  ${YELLOW}Pressione Ctrl+C para parar${RESET}"
echo ""

# Start Flask
FLASK_APP=run.py \
FLASK_ENV="${FLASK_ENV:-development}" \
FLASK_DEBUG="${FLASK_DEBUG:-1}" \
python3 run.py
