"""WHAZIDEIA SaaS — Flask + SQLAlchemy (Postgres). TODO o Python neste arquivo.

  Dev:   DEBUG=1 python app.py            (SQLite local; o código de e-mail aparece no log)
  Prod:  gunicorn app:app                 (o docker-entrypoint.sh já roda python app.py init-db antes)
  CLI:   python app.py init-db

Procure por "# ═══" para pular entre as seções.

PRIVACIDADE: o conteúdo do usuário vive só na tabela user_data. O painel admin NUNCA lê user_data.conteudo
(só soma o tamanho em bytes). Mantenha assim ao mexer no admin.
"""
import hmac
import json
import logging
import os
import random
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from flask import (Flask, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request,
                   session)
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape
from sqlalchemy import delete, event, func, inspect, or_, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG — tudo vem de variáveis de ambiente (.env no local, painel de env no Dokploy)
# ═══════════════════════════════════════════════════════════════════════════
def _bool(nome, padrao=False):
    v = os.environ.get(nome)
    if v is None or v.strip() == "":
        return padrao
    return v.strip().lower() in ("1", "true", "yes", "sim", "on")


def _int(nome, padrao):
    try:
        return int(os.environ.get(nome, "").strip() or padrao)
    except ValueError:
        return padrao


DEBUG = _bool("DEBUG")


def _secret_key():
    chave = os.environ.get("SECRET_KEY", "").strip()
    if not chave:
        if DEBUG:
            return "dev-inseguro-nao-use-em-producao"
        raise RuntimeError("SECRET_KEY não definida. Gere com: python -c \"import secrets; print(secrets.token_hex(32))\"")
    if not DEBUG and len(chave) < 32:
        raise RuntimeError("SECRET_KEY fraca. Use pelo menos 32 caracteres aleatórios.")
    return chave


def _db_url():
    """Padrão: SQLite em DATA_DIR/db.sqlite (no Docker: volume /data). DATABASE_URL só se você quiser outro banco."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        pasta = os.path.abspath(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
        os.makedirs(pasta, exist_ok=True)
        return "sqlite:///" + os.path.join(pasta, "db.sqlite")
    if url.startswith("postgres://"):
        url = "postgresql+psycopg2://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


# ═══════════════════════════════════════════════════════════════════════════
# EXTENSÕES
# ═══════════════════════════════════════════════════════════════════════════
db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _pragmas_sqlite(conexao, _registro):
    """SQLite: WAL, espera em vez de 'database is locked' e FKs ligadas (cascade funciona)."""
    if isinstance(conexao, sqlite3.Connection):
        cur = conexao.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


# ═══════════════════════════════════════════════════════════════════════════
# MODELS
#   users        conta (nome, e-mail, status) — é tudo que o admin enxerga
#   email_tokens códigos de 6 dígitos (verificar e-mail / redefinir senha), guardados só como hash
#   user_data    conteúdo do app, 1 linha por (usuário, chave). O admin não lê.
#   admins       login do painel /admin
# ═══════════════════════════════════════════════════════════════════════════
def agora():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (db.CheckConstraint("status in ('pendente','ativo','bloqueado')", name="ck_users_status"),)
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(254), nullable=False)                      # como a pessoa digitou (minúsculo)
    email_norm = db.Column(db.String(254), nullable=False, unique=True)    # chave de unicidade (gmail sem pontos/+tag)
    senha_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(12), nullable=False, default="pendente", index=True)
    email_verificado_em = db.Column(db.DateTime)
    criado_por_admin = db.Column(db.Boolean, nullable=False, default=False)
    trocar_senha = db.Column(db.Boolean, nullable=False, default=False)
    sessao_versao = db.Column(db.Integer, nullable=False, default=1)       # +1 derruba todas as sessões da pessoa
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    ultimo_login = db.Column(db.DateTime)


class EmailToken(db.Model):
    __tablename__ = "email_tokens"
    __table_args__ = (db.Index("ix_tokens_user_tipo", "user_id", "tipo"),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tipo = db.Column(db.String(12), nullable=False)                        # verificar | resetar
    codigo_hash = db.Column(db.String(64), nullable=False)
    expira_em = db.Column(db.DateTime, nullable=False)
    tentativas = db.Column(db.Integer, nullable=False, default=0)
    usado_em = db.Column(db.DateTime)
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class UserData(db.Model):
    __tablename__ = "user_data"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    chave = db.Column(db.String(60), primary_key=True)                     # ex.: mindOSData, mindOS_vida_v3
    conteudo = db.Column(db.Text, nullable=False, default="")
    versao = db.Column(db.Integer, nullable=False, default=1)              # trava otimista (outra aba/aparelho)
    atualizado_em = db.Column(db.DateTime, nullable=False, default=agora)


class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(60), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class RateHit(db.Model):
    """Rate limit persistente (vale entre os workers do gunicorn)."""
    __tablename__ = "rate_hits"
    __table_args__ = (db.Index("ix_rate_chave_ts", "chave", "ts"),)
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    ts = db.Column(db.Float, nullable=False)


class SchemaInfo(db.Model):
    __tablename__ = "schema_info"
    id = db.Column(db.Integer, primary_key=True)
    versao = db.Column(db.Integer, nullable=False, default=1)


# ═══════════════════════════════════════════════════════════════════════════
# DBINIT — criação/migração idempotente (o entrypoint roda a cada start do container)
# ═══════════════════════════════════════════════════════════════════════════
def adicionar_coluna(tabela, coluna, ddl):
    """Helper p/ migrações futuras: ALTER TABLE ADD COLUMN só se a coluna ainda não existe."""
    if coluna not in {c["name"] for c in inspect(db.engine).get_columns(tabela)}:
        db.session.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {ddl}"))
        db.session.commit()


# Exemplo: def _v2(): adicionar_coluna("users", "plano", "VARCHAR(20)")   →   MIGRACOES = [(2, _v2)]
MIGRACOES = []


def sincronizar_admin():
    """O .env é a fonte da verdade do admin: cria o usuário e atualiza a senha se ela mudou no .env."""
    usuario = os.environ.get("ADMIN_USER", "").strip()
    senha = os.environ.get("ADMIN_PASS", "")
    if not usuario or not senha:
        logging.getLogger(__name__).warning("ADMIN_USER/ADMIN_PASS não definidos: painel /admin sem login.")
        return
    if len(senha) < 10:
        raise RuntimeError("ADMIN_PASS precisa ter pelo menos 10 caracteres.")
    adm = db.session.scalar(select(Admin).where(Admin.usuario == usuario))
    if adm is None:
        db.session.add(Admin(usuario=usuario, senha_hash=generate_password_hash(senha)))
    elif not check_password_hash(adm.senha_hash, senha):
        adm.senha_hash = generate_password_hash(senha)
    db.session.commit()


def iniciar_banco(app):
    with app.app_context():
        db.create_all()
        info = db.session.get(SchemaInfo, 1)
        if info is None:
            info = SchemaInfo(id=1, versao=1)
            db.session.add(info)
            db.session.commit()
        for versao, fn in MIGRACOES:
            if versao > info.versao:
                fn()
                info.versao = versao
                db.session.commit()
        sincronizar_admin()
        limpar_pendentes()
        return info.versao


# ═══════════════════════════════════════════════════════════════════════════
# UTILS — validação, e-mail normalizado, rate limit, CSRF
# ═══════════════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
CHAVE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
MAX_CHAVES = 40
CODIGO_MIN = 30           # validade do código (minutos)
CODIGO_TENTATIVAS = 5
REENVIO_SEG = 60
DUMMY_HASH = generate_password_hash(secrets.token_hex(8))   # tempo de resposta igual p/ e-mail inexistente


def norm_email(e):
    """Chave única de e-mail. Gmail: a.b+x@gmail.com e ab@gmail.com são a mesma caixa → mesma conta."""
    e = (e or "").strip().lower()
    if "@" not in e:
        return e
    local, dom = e.rsplit("@", 1)
    if dom in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        dom = "gmail.com"
    return f"{local}@{dom}"


def limpar_nome(n):
    n = re.sub(r"[\x00-\x1f\x7f]", "", n or "")
    return re.sub(r"\s+", " ", n).strip()


def validar_nome_email(nome, email):
    if not 2 <= len(nome) <= 80:
        return "Informe seu nome (2 a 80 caracteres)."
    if len(email) > 254 or not EMAIL_RE.match(email) or not norm_email(email).split("@")[0]:
        return "E-mail inválido."
    return None


def validar_senha(senha, confirmar, email=""):
    if len(senha) < 8:
        return "A senha precisa ter pelo menos 8 caracteres."
    if len(senha) > 128:
        return "A senha pode ter no máximo 128 caracteres."
    if email and senha.lower() == email.lower():
        return "A senha não pode ser igual ao e-mail."
    if confirmar is not None and senha != confirmar:
        return "As senhas não conferem."
    return None


def gerar_senha():
    alfabeto = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alfabeto) for _ in range(12))


def safe_next(url):
    if not url or not url.startswith("/") or url.startswith("//") or "\\" in url:
        return None
    return url


def escape_like(txt):
    return txt.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def filtro_data_br(v, hora=True):
    if not v:
        return "—"
    local = v.replace(tzinfo=timezone.utc).astimezone(current_app.config["TZ"])
    return local.strftime("%d/%m/%Y %H:%M" if hora else "%d/%m/%Y")


def permitir(chave, maximo, janela):
    """True se ainda cabe na cota (e já registra a tentativa). Tabela rate_hits, vale entre workers."""
    chave = chave[:120]
    n = db.session.scalar(select(func.count(RateHit.id)).where(RateHit.chave == chave, RateHit.ts > time.time() - janela))
    if (n or 0) >= maximo:
        return False
    db.session.add(RateHit(chave=chave, ts=time.time()))
    db.session.commit()
    if random.random() < 0.01:
        db.session.execute(delete(RateHit).where(RateHit.ts < time.time() - 86400))
        db.session.commit()
    return True


def csrf_token():
    t = session.get("_csrf")
    if not t:
        t = session["_csrf"] = secrets.token_urlsafe(32)
    return t


def limpar_pendentes():
    """Apaga cadastros que nunca confirmaram o e-mail (48h) — libera o e-mail e não acumula lixo."""
    limite = agora() - timedelta(hours=48)
    ids = db.session.scalars(select(User.id).where(User.status == "pendente", User.criado_em < limite,
                                                   User.criado_por_admin.is_(False))).all()
    for uid in ids:
        apagar_usuario(uid)


def apagar_usuario(uid):
    """Exclusão definitiva (LGPD): dados, códigos e conta."""
    db.session.execute(delete(UserData).where(UserData.user_id == uid))
    db.session.execute(delete(EmailToken).where(EmailToken.user_id == uid))
    db.session.execute(delete(User).where(User.id == uid))
    db.session.commit()


# ═══════════════════════════════════════════════════════════════════════════
# E-MAIL — SMTP em thread (a requisição não espera) + códigos de 6 dígitos
# ═══════════════════════════════════════════════════════════════════════════
def smtp_configurado():
    c = current_app.config
    return bool(c["SMTP_SERVER"] and c["SMTP_USER"] and c["SMTP_PASS"])


def enviar_email(para, assunto, texto):
    c = current_app.config
    log = current_app.logger
    if not smtp_configurado():
        log.warning("SMTP não configurado: e-mail para %s não enviado.", para)
        if DEBUG:
            log.info("[DEBUG] e-mail para %s | %s\n%s", para, assunto, texto)
        return
    cfg = {k: c[k] for k in ("SMTP_SERVER", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "SMTP_SECURITY", "APP_NAME")}

    def _enviar():
        try:
            msg = EmailMessage()
            msg["From"] = formataddr((cfg["APP_NAME"], cfg["SMTP_FROM"] or cfg["SMTP_USER"]))
            msg["To"] = para
            msg["Subject"] = assunto
            msg.set_content(texto)
            if cfg["SMTP_SECURITY"] == "ssl":
                s = smtplib.SMTP_SSL(cfg["SMTP_SERVER"], cfg["SMTP_PORT"], timeout=15)
            else:
                s = smtplib.SMTP(cfg["SMTP_SERVER"], cfg["SMTP_PORT"], timeout=15)
                if cfg["SMTP_SECURITY"] == "starttls":
                    s.starttls()
            with s:
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
                s.send_message(msg)
        except Exception:
            log.exception("Falha ao enviar e-mail para %s", para)

    threading.Thread(target=_enviar, daemon=True).start()


def _hash_codigo(uid, tipo, codigo):
    chave = current_app.config["SECRET_KEY"].encode()
    return hmac.new(chave, f"{uid}:{tipo}:{codigo}".encode(), "sha256").hexdigest()


def emitir_codigo(u, tipo):
    """Invalida códigos antigos, cria um novo (hash no banco) e manda o texto por e-mail."""
    db.session.execute(update(EmailToken).where(EmailToken.user_id == u.id, EmailToken.tipo == tipo,
                                                EmailToken.usado_em.is_(None)).values(usado_em=agora()))
    codigo = f"{secrets.randbelow(10 ** 6):06d}"
    db.session.add(EmailToken(user_id=u.id, tipo=tipo, codigo_hash=_hash_codigo(u.id, tipo, codigo),
                              expira_em=agora() + timedelta(minutes=CODIGO_MIN)))
    db.session.commit()
    app_nome = current_app.config["APP_NAME"]
    if tipo == "verificar":
        assunto, motivo = f"{codigo} é seu código do {app_nome}", "confirmar seu e-mail"
    else:
        assunto, motivo = f"{codigo} é seu código para redefinir a senha", "redefinir sua senha"
    enviar_email(u.email, assunto,
                 f"Olá, {u.nome}!\n\nSeu código para {motivo} no {app_nome}:\n\n    {codigo}\n\n"
                 f"Ele vale por {CODIGO_MIN} minutos. Se não foi você, ignore este e-mail.\n")


def codigo_recente(u, tipo):
    t = db.session.scalar(select(EmailToken.criado_em).where(EmailToken.user_id == u.id, EmailToken.tipo == tipo)
                          .order_by(EmailToken.id.desc()).limit(1))
    return bool(t and t > agora() - timedelta(seconds=REENVIO_SEG))


def conferir_codigo(u, tipo, codigo):
    """(ok, mensagem). Tentativas contadas de forma atômica (não dá pra burlar com requisições paralelas)."""
    t = db.session.scalar(select(EmailToken).where(EmailToken.user_id == u.id, EmailToken.tipo == tipo,
                                                   EmailToken.usado_em.is_(None)).order_by(EmailToken.id.desc()))
    if not t or t.expira_em < agora():
        return False, "Código expirado. Peça um novo."
    res = db.session.execute(update(EmailToken).where(EmailToken.id == t.id, EmailToken.tentativas < CODIGO_TENTATIVAS)
                             .values(tentativas=EmailToken.tentativas + 1))
    db.session.commit()
    if res.rowcount == 0:
        return False, "Muitas tentativas. Peça um novo código."
    if hmac.compare_digest(t.codigo_hash, _hash_codigo(u.id, tipo, codigo)):
        db.session.execute(update(EmailToken).where(EmailToken.id == t.id).values(usado_em=agora()))
        db.session.commit()
        return True, ""
    return False, "Código incorreto."


# ═══════════════════════════════════════════════════════════════════════════
# AUTH — sessão assinada (cookie) + checagem no banco a cada requisição
# ═══════════════════════════════════════════════════════════════════════════
def usuario_atual():
    if "_usuario" in g:
        return g._usuario
    g._usuario = None
    s = session.get("u")
    if s:
        u = db.session.get(User, s.get("id"))
        if u and u.status == "ativo" and u.sessao_versao == s.get("v"):
            g._usuario = u
        else:
            session.pop("u", None)
    return g._usuario


def entrar(u):
    """Nova sessão (troca o CSRF e evita fixação de sessão)."""
    session.clear()
    session.permanent = True
    session["u"] = {"id": u.id, "v": u.sessao_versao}


def login_obrigatorio(f):
    @wraps(f)
    def wrapper(*a, **k):
        u = usuario_atual()
        api = request.path.startswith("/api/")
        if not u:
            if api:
                return jsonify(ok=False, erro="Sessão expirada. Entre de novo."), 401
            return redirect("/login" + (f"?next={request.full_path.rstrip('?')}" if request.method == "GET" else ""))
        return f(*a, **k)
    return wrapper


def admin_atual():
    a = session.get("adm")
    horas = current_app.config["ADMIN_SESSAO_HORAS"]
    if not a or time.time() - a.get("t", 0) > horas * 3600:
        return None
    adm = db.session.get(Admin, a.get("id"))
    if not adm or adm.senha_hash[-16:] != a.get("h"):
        return None
    return adm


def admin_obrigatorio(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not admin_atual():
            session.pop("adm", None)
            return redirect("/admin/login")
        return f(*a, **k)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# APP FACTORY
# ═══════════════════════════════════════════════════════════════════════════
def create_app(config=None):
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=None)
    app.url_map.strict_slashes = False
    app.config.update(
        SECRET_KEY=_secret_key(),
        SQLALCHEMY_DATABASE_URI=_db_url(),
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=_int("MAX_DADO_KB", 2048) * 1024 + 64 * 1024,
        MAX_DADO_KB=_int("MAX_DADO_KB", 2048),
        SESSION_COOKIE_NAME="wz_sessao",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_bool("COOKIE_SECURE", not DEBUG),
        PERMANENT_SESSION_LIFETIME=timedelta(days=_int("SESSAO_DIAS", 30)),
        ADMIN_SESSAO_HORAS=_int("ADMIN_SESSAO_HORAS", 8),
        APP_NAME=os.environ.get("APP_NAME", "WHAZIDEIA").strip() or "WHAZIDEIA",
        CADASTRO_ABERTO=_bool("CADASTRO_ABERTO", True),
        PROXY_HOPS=_int("PROXY_HOPS", 1),
        TZ=ZoneInfo(os.environ.get("TZ_NAME", "America/Sao_Paulo")),
        SMTP_SERVER=os.environ.get("SMTP_SERVER", "").strip(),
        SMTP_PORT=_int("SMTP_PORT", 587),
        SMTP_USER=os.environ.get("SMTP_USER", "").strip(),
        SMTP_PASS=os.environ.get("SMTP_PASS", ""),
        SMTP_FROM=os.environ.get("SMTP_FROM", "").strip(),
    )
    porta = app.config["SMTP_PORT"]
    app.config["SMTP_SECURITY"] = os.environ.get("SMTP_SECURITY", "ssl" if porta == 465 else "starttls").strip().lower()
    if config:
        app.config.update(config)
    logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if app.config["PROXY_HOPS"] > 0:
        h = app.config["PROXY_HOPS"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=h, x_proto=h, x_host=h)

    db.init_app(app)
    app.add_template_filter(filtro_data_br, "data_br")

    @app.context_processor
    def _contexto():
        return {"csrf_token": csrf_token, "app_nome": app.config["APP_NAME"],
                "cadastro_aberto": app.config["CADASTRO_ABERTO"]}

    @app.before_request
    def _csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            enviado = request.headers.get("X-CSRF-Token") or request.form.get("_csrf") or ""
            esperado = session.get("_csrf", "")
            if not esperado or not hmac.compare_digest(enviado, esperado):
                abort(400)

    @app.after_request
    def _seguranca(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    MENS = {400: "Pedido inválido ou sessão expirada. Volte, recarregue a página e tente de novo.",
            404: "Página não encontrada.", 405: "Ação não permitida.", 429: "Muitas tentativas. Aguarde alguns minutos.",
            500: "Erro interno. Tente novamente em instantes."}

    def responder(e):
        codigo = getattr(e, "code", 500) or 500
        msg = MENS.get(codigo, "Erro")
        if codigo == 413:
            msg = f"Os dados enviados são grandes demais (limite de {app.config['MAX_DADO_KB']} KB por item)."
        if request.path.startswith("/api/"):
            return jsonify(ok=False, erro=msg), codigo
        if codigo == 500:
            app.logger.exception("Erro 500 em %s", request.path)
        return render_template("erro.html", codigo=codigo, mensagem=msg), codigo

    for c in (400, 404, 405, 413, 429, 500):
        app.register_error_handler(c, responder)

    registrar_rotas(app)
    return app


# ═══════════════════════════════════════════════════════════════════════════
# ROTAS
# ═══════════════════════════════════════════════════════════════════════════
def registrar_rotas(app):
    cfg = app.config

    def ip():
        return request.remote_addr or "?"

    # ── básicos ────────────────────────────────────────────────────────────
    @app.get("/healthz")
    def healthz():
        db.session.execute(text("SELECT 1"))
        return Response("ok", mimetype="text/plain")

    @app.get("/logo.png")
    def logo():
        r = Response((BASE_DIR / "static" / "logo.png").read_bytes(), mimetype="image/png")
        r.headers["Cache-Control"] = "public, max-age=604800"
        return r

    @app.get("/")
    def raiz():
        return redirect("/app" if usuario_atual() else "/login")

    # ── cadastro (grátis) + confirmação de e-mail ──────────────────────────
    @app.route("/cadastro", methods=["GET", "POST"])
    def cadastro():
        if usuario_atual():
            return redirect("/app")
        if not cfg["CADASTRO_ABERTO"]:
            return render_template("cadastro.html", fechado=True)
        if request.method == "GET":
            return render_template("cadastro.html")
        f = request.form
        if f.get("website"):                       # honeypot: bot preencheu o campo escondido
            return redirect("/verificar")
        if not permitir(f"cad:{ip()}", 6, 3600):
            flash("Muitas tentativas de cadastro. Tente mais tarde.", "erro")
            return render_template("cadastro.html"), 429
        if not smtp_configurado() and not DEBUG:
            flash("Cadastro indisponível no momento (envio de e-mail não configurado).", "erro")
            return render_template("cadastro.html"), 503
        nome, email = limpar_nome(f.get("nome")), (f.get("email") or "").strip().lower()
        senha, conf = f.get("senha") or "", f.get("confirmar") or ""
        erro = validar_nome_email(nome, email) or validar_senha(senha, conf, email)
        if erro:
            flash(erro, "erro")
            return render_template("cadastro.html", nome=nome, email=email), 422
        if random.random() < 0.05:
            limpar_pendentes()
        en = norm_email(email)
        u = db.session.scalar(select(User).where(User.email_norm == en))
        duplicado = "Já existe uma conta com este e-mail. Entre ou recupere a senha."
        if u and u.status != "pendente":
            flash(duplicado, "erro")
            return render_template("cadastro.html", nome=nome, email=email), 409
        if u:                                      # pendente: quem confirmar o e-mail define a conta
            u.nome, u.email, u.senha_hash = nome, email, generate_password_hash(senha)
            db.session.commit()
        else:
            u = User(nome=nome, email=email, email_norm=en, senha_hash=generate_password_hash(senha), status="pendente")
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:                 # corrida: outro cadastro igual entrou no mesmo instante
                db.session.rollback()
                flash(duplicado, "erro")
                return render_template("cadastro.html", nome=nome, email=email), 409
        if not codigo_recente(u, "verificar"):
            emitir_codigo(u, "verificar")
        session.clear()
        session["pend"] = u.id
        return redirect("/verificar")

    def _pendente():
        uid = session.get("pend")
        u = db.session.get(User, uid) if uid else None
        return u if u and u.status == "pendente" else None

    @app.route("/verificar", methods=["GET", "POST"])
    def verificar():
        u = _pendente()
        if not u:
            return redirect("/login")
        if request.method == "GET":
            return render_template("verificar.html", email=u.email)
        if not permitir(f"ver:{ip()}", 20, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return render_template("verificar.html", email=u.email), 429
        codigo = re.sub(r"\D", "", request.form.get("codigo", ""))
        ok, msg = conferir_codigo(u, "verificar", codigo)
        if not ok:
            flash(msg, "erro")
            return render_template("verificar.html", email=u.email), 422
        u.status, u.email_verificado_em, u.ultimo_login = "ativo", agora(), agora()
        db.session.commit()
        entrar(u)
        return redirect("/app")

    @app.post("/verificar/reenviar")
    def verificar_reenviar():
        u = _pendente()
        if not u:
            return redirect("/login")
        if codigo_recente(u, "verificar"):
            flash("Aguarde um minuto para pedir outro código.", "aviso")
        elif not permitir(f"reenv:{u.id}", 5, 3600):
            flash("Limite de reenvios atingido. Tente mais tarde.", "erro")
        else:
            emitir_codigo(u, "verificar")
            flash("Enviamos um novo código.", "ok")
        return redirect("/verificar")

    # ── login / sair ───────────────────────────────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if usuario_atual():
            return redirect("/app")
        if request.method == "GET":
            return render_template("login.html", proximo=request.args.get("next", ""))
        email = (request.form.get("email") or "").strip().lower()
        senha = request.form.get("senha") or ""
        proximo = request.form.get("next", "")
        en = norm_email(email)
        if not permitir(f"login:{ip()}", 10, 600) or not permitir(f"loginu:{en}", 8, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return render_template("login.html", email=email, proximo=proximo), 429
        u = db.session.scalar(select(User).where(User.email_norm == en)) if en else None
        if not check_password_hash(u.senha_hash if u else DUMMY_HASH, senha) or not u:
            flash("E-mail ou senha incorretos.", "erro")
            return render_template("login.html", email=email, proximo=proximo), 401
        if u.status == "bloqueado":
            flash("Esta conta está bloqueada. Fale com o suporte.", "erro")
            return render_template("login.html", email=email, proximo=proximo), 403
        if u.status == "pendente":
            if not codigo_recente(u, "verificar"):
                emitir_codigo(u, "verificar")
            session.clear()
            session["pend"] = u.id
            return redirect("/verificar")
        u.ultimo_login = agora()
        db.session.commit()
        entrar(u)
        return redirect(safe_next(proximo) or "/app")

    @app.post("/sair")
    def sair():
        session.clear()
        return redirect("/login")

    # ── recuperar senha (por código) ───────────────────────────────────────
    @app.route("/esqueci", methods=["GET", "POST"])
    def esqueci():
        if request.method == "GET":
            return render_template("esqueci.html")
        email = (request.form.get("email") or "").strip().lower()
        en = norm_email(email)
        if not permitir(f"esq:{ip()}", 5, 3600) or not permitir(f"esqu:{en}", 3, 3600):
            flash("Muitas tentativas. Tente mais tarde.", "erro")
            return render_template("esqueci.html"), 429
        u = db.session.scalar(select(User).where(User.email_norm == en)) if EMAIL_RE.match(email) else None
        if u and u.status == "ativo" and not codigo_recente(u, "resetar"):
            emitir_codigo(u, "resetar")
        session.clear()
        session["rst"] = en                        # resposta igual exista a conta ou não
        flash("Se existir uma conta com esse e-mail, enviamos um código.", "ok")
        return redirect("/redefinir")

    @app.route("/redefinir", methods=["GET", "POST"])
    def redefinir():
        en = session.get("rst")
        if not en:
            return redirect("/esqueci")
        if request.method == "GET":
            return render_template("redefinir.html")
        if not permitir(f"red:{ip()}", 20, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return render_template("redefinir.html"), 429
        nova, conf = request.form.get("senha") or "", request.form.get("confirmar") or ""
        erro = validar_senha(nova, conf)
        if erro:
            flash(erro, "erro")
            return render_template("redefinir.html"), 422
        u = db.session.scalar(select(User).where(User.email_norm == en))
        codigo = re.sub(r"\D", "", request.form.get("codigo", ""))
        ok, msg = (False, "Código incorreto ou expirado.")
        if u and u.status == "ativo":
            ok, msg = conferir_codigo(u, "resetar", codigo)
        if not ok:
            flash(msg, "erro")
            return render_template("redefinir.html"), 422
        u.senha_hash, u.trocar_senha, u.sessao_versao = generate_password_hash(nova), False, u.sessao_versao + 1
        db.session.commit()
        session.clear()
        flash("Senha alterada. Entre com a nova senha.", "ok")
        return redirect("/login")

    # ── o app (HTML do mind OS com os dados do usuário injetados) ──────────
    @app.get("/app")
    @login_obrigatorio
    def mindos():
        u = usuario_atual()
        linhas = db.session.execute(select(UserData.chave, UserData.conteudo, UserData.versao)
                                    .where(UserData.user_id == u.id)).all()
        boot = {"data": {r.chave: r.conteudo for r in linhas}, "v": {r.chave: r.versao for r in linhas},
                "csrf": csrf_token()}
        js = json.dumps(boot).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        html = (BASE_DIR / "templates" / "mindos.html").read_text(encoding="utf-8")
        html = html.replace("<!--MOS_BOOT-->", f"<script>window.__MOS_BOOT={js};</script>", 1)
        html = html.replace("<!--MOS_USER-->", str(escape(f"{u.nome} · {u.email}")), 1)
        return Response(html, mimetype="text/html")

    # ── API de dados (substitui o localStorage) ────────────────────────────
    @app.put("/api/data/<chave>")
    @login_obrigatorio
    def api_salvar(chave):
        if not CHAVE_RE.match(chave):
            abort(404)
        d = request.get_json(silent=True)
        if not isinstance(d, dict):
            return jsonify(ok=False, erro="JSON inválido."), 400
        conteudo, base = d.get("conteudo"), d.get("versao", 0)
        if not isinstance(base, int) or isinstance(base, bool) or base < 0:
            return jsonify(ok=False, erro="Versão inválida."), 400
        if conteudo is not None:
            if not isinstance(conteudo, str) or "\x00" in conteudo:
                return jsonify(ok=False, erro="Conteúdo inválido."), 400
            if len(conteudo.encode("utf-8")) > cfg["MAX_DADO_KB"] * 1024:
                return jsonify(ok=False, erro=f"Esse item passou de {cfg['MAX_DADO_KB']} KB."), 413
        uid = usuario_atual().id
        linha = db.session.get(UserData, (uid, chave))
        if conteudo is None:                       # remover a chave
            if linha is not None:
                res = db.session.execute(delete(UserData).where(UserData.user_id == uid, UserData.chave == chave,
                                                                UserData.versao == base))
                db.session.commit()
                if res.rowcount == 0:
                    return jsonify(ok=False, erro="conflito", versao=linha.versao), 409
            return jsonify(ok=True, versao=0)
        if linha is None:
            if base != 0:
                return jsonify(ok=False, erro="conflito", versao=0), 409
            n = db.session.scalar(select(func.count()).select_from(UserData).where(UserData.user_id == uid))
            if (n or 0) >= MAX_CHAVES:
                return jsonify(ok=False, erro="Limite de itens atingido."), 422
            db.session.add(UserData(user_id=uid, chave=chave, conteudo=conteudo, versao=1))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return jsonify(ok=False, erro="conflito", versao=1), 409
            return jsonify(ok=True, versao=1)
        res = db.session.execute(update(UserData).where(UserData.user_id == uid, UserData.chave == chave,
                                                        UserData.versao == base)
                                 .values(conteudo=conteudo, versao=base + 1, atualizado_em=agora()))
        db.session.commit()
        if res.rowcount == 0:
            atual = db.session.scalar(select(UserData.versao).where(UserData.user_id == uid, UserData.chave == chave))
            return jsonify(ok=False, erro="conflito", versao=atual or 0), 409
        return jsonify(ok=True, versao=base + 1)

    # ── minha conta ────────────────────────────────────────────────────────
    @app.get("/conta")
    @login_obrigatorio
    def conta():
        return render_template("conta.html", u=usuario_atual())

    @app.post("/conta/nome")
    @login_obrigatorio
    def conta_nome():
        u = usuario_atual()
        nome = limpar_nome(request.form.get("nome"))
        if not 2 <= len(nome) <= 80:
            flash("Informe seu nome (2 a 80 caracteres).", "erro")
        else:
            u.nome = nome
            db.session.commit()
            flash("Nome atualizado.", "ok")
        return redirect("/conta")

    @app.post("/conta/senha")
    @login_obrigatorio
    def conta_senha():
        u = usuario_atual()
        if not permitir(f"senha:{u.id}", 8, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return redirect("/conta")
        atual, nova, conf = request.form.get("atual") or "", request.form.get("senha") or "", request.form.get("confirmar") or ""
        erro = None if check_password_hash(u.senha_hash, atual) else "A senha atual está incorreta."
        erro = erro or validar_senha(nova, conf, u.email)
        if erro:
            flash(erro, "erro")
            return redirect("/conta")
        u.senha_hash, u.trocar_senha, u.sessao_versao = generate_password_hash(nova), False, u.sessao_versao + 1
        db.session.commit()
        entrar(u)                                  # derruba as outras sessões, mantém esta
        flash("Senha alterada.", "ok")
        return redirect("/conta")

    @app.get("/conta/exportar")
    @login_obrigatorio
    def conta_exportar():
        u = usuario_atual()
        linhas = db.session.execute(select(UserData.chave, UserData.conteudo).where(UserData.user_id == u.id)).all()
        dados = {}
        for chave, conteudo in linhas:
            try:
                dados[chave] = json.loads(conteudo)
            except ValueError:
                dados[chave] = conteudo
        out = {"nome": u.nome, "email": u.email, "criado_em": u.criado_em.isoformat() + "Z", "dados": dados}
        return Response(json.dumps(out, ensure_ascii=False, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=meus-dados.json"})

    @app.post("/conta/excluir")
    @login_obrigatorio
    def conta_excluir():
        u = usuario_atual()
        if not permitir(f"excl:{u.id}", 5, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return redirect("/conta")
        if not request.form.get("confirmo") or not check_password_hash(u.senha_hash, request.form.get("senha") or ""):
            flash("Para excluir, marque a confirmação e digite sua senha.", "erro")
            return redirect("/conta")
        apagar_usuario(u.id)
        session.clear()
        flash("Sua conta e todos os seus dados foram excluídos.", "ok")
        return redirect("/login")

    # ═══ ADMIN (/admin) — só dados da conta; nunca o conteúdo do usuário ═══
    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "GET":
            return render_template("admin_login.html")
        if not permitir(f"adm:{ip()}", 6, 600):
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return render_template("admin_login.html"), 429
        usuario, senha = (request.form.get("usuario") or "").strip(), request.form.get("senha") or ""
        adm = db.session.scalar(select(Admin).where(Admin.usuario == usuario))
        if not check_password_hash(adm.senha_hash if adm else DUMMY_HASH, senha) or not adm:
            flash("Usuário ou senha incorretos.", "erro")
            return render_template("admin_login.html"), 401
        session.clear()
        session["adm"] = {"id": adm.id, "h": adm.senha_hash[-16:], "t": time.time()}
        return redirect("/admin")

    @app.post("/admin/sair")
    def admin_sair():
        session.clear()
        return redirect("/admin/login")

    def render_admin(**extra):
        q = (request.values.get("q") or "").strip()
        status = request.values.get("status") or ""
        pagina = max(1, request.values.get("p", 1, type=int) or 1)
        por_pagina = 25
        tamanho = func.coalesce(select(func.sum(func.length(UserData.conteudo)))      # só o tamanho, nunca o conteúdo
                                .where(UserData.user_id == User.id).correlate(User).scalar_subquery(), 0)
        filtros = []
        if q:
            like = f"%{escape_like(q.lower())}%"
            filtros.append(or_(func.lower(User.nome).like(like, escape="\\"), User.email.like(like, escape="\\")))
        if status in ("pendente", "ativo", "bloqueado"):
            filtros.append(User.status == status)
        total = db.session.scalar(select(func.count()).select_from(User).where(*filtros)) or 0
        usuarios = db.session.execute(
            select(User.id, User.nome, User.email, User.status, User.email_verificado_em, User.criado_por_admin,
                   User.criado_em, User.ultimo_login, tamanho.label("bytes")).where(*filtros)
            .order_by(User.id.desc()).limit(por_pagina).offset((pagina - 1) * por_pagina)).all()
        por_status = dict(db.session.execute(select(User.status, func.count()).group_by(User.status)).all())
        novos7 = db.session.scalar(select(func.count()).select_from(User).where(User.criado_em > agora() - timedelta(days=7))) or 0
        return render_template("admin.html", usuarios=usuarios, total=total, pagina=pagina, por_pagina=por_pagina,
                               q=q, status=status, por_status=por_status, novos7=novos7, admin=admin_atual(), **extra)

    @app.get("/admin")
    @admin_obrigatorio
    def admin_lista():
        return render_admin()

    @app.post("/admin/usuarios")
    @admin_obrigatorio
    def admin_criar():
        nome, email = limpar_nome(request.form.get("nome")), (request.form.get("email") or "").strip().lower()
        senha = (request.form.get("senha") or "").strip() or gerar_senha()
        erro = validar_nome_email(nome, email) or validar_senha(senha, None, email)
        if not erro and db.session.scalar(select(User.id).where(User.email_norm == norm_email(email))):
            erro = "Já existe uma conta com este e-mail."
        if erro:
            flash(erro, "erro")
            return render_admin(), 422
        u = User(nome=nome, email=email, email_norm=norm_email(email), senha_hash=generate_password_hash(senha),
                 status="ativo", email_verificado_em=agora(), criado_por_admin=True, trocar_senha=True)
        db.session.add(u)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Já existe uma conta com este e-mail.", "erro")
            return render_admin(), 409
        return render_admin(segredo={"email": email, "senha": senha, "tipo": "criada"})   # aparece uma única vez

    def _alvo(uid):
        u = db.session.get(User, uid)
        if not u:
            abort(404)
        return u

    @app.post("/admin/usuarios/<int:uid>/bloquear")
    @admin_obrigatorio
    def admin_bloquear(uid):
        u = _alvo(uid)
        u.status, u.sessao_versao = "bloqueado", u.sessao_versao + 1
        db.session.commit()
        flash(f"{u.email} foi bloqueado e desconectado.", "ok")
        return redirect("/admin")

    @app.post("/admin/usuarios/<int:uid>/desbloquear")
    @admin_obrigatorio
    def admin_desbloquear(uid):
        u = _alvo(uid)
        u.status = "ativo" if u.email_verificado_em else "pendente"
        db.session.commit()
        flash(f"{u.email} foi desbloqueado.", "ok")
        return redirect("/admin")

    @app.post("/admin/usuarios/<int:uid>/senha")
    @admin_obrigatorio
    def admin_senha(uid):
        u = _alvo(uid)
        senha = gerar_senha()
        u.senha_hash, u.trocar_senha, u.sessao_versao = generate_password_hash(senha), True, u.sessao_versao + 1
        db.session.commit()
        return render_admin(segredo={"email": u.email, "senha": senha, "tipo": "redefinida"})

    @app.post("/admin/usuarios/<int:uid>/excluir")
    @admin_obrigatorio
    def admin_excluir(uid):
        u = _alvo(uid)
        if (request.form.get("confirmar") or "").strip().lower() != u.email:
            flash("Para excluir, digite o e-mail da conta exatamente como aparece.", "erro")
            return redirect("/admin")
        email = u.email
        apagar_usuario(uid)
        flash(f"{email} e todos os dados dessa conta foram excluídos.", "ok")
        return redirect("/admin")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
app = create_app()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "init-db":
        print(f"Banco pronto (schema v{iniciar_banco(app)}).")
    elif cmd == "run":
        iniciar_banco(app)
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=_int("PORT", 8000), debug=DEBUG)
    else:
        sys.exit("Uso: python app.py [run | init-db]")


if __name__ == "__main__":
    main()
