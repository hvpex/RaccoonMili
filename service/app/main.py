import os
import time
import hmac
import base64
import hashlib
import sqlite3
import secrets
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request, Form, Path
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

APP_NAME = "RaccoonMili"
DB_PATH = os.environ.get("DB_PATH", "/home/user/data/app.db")
SECRET = os.environ.get("APP_SECRET", "MiliEnot")

app = FastAPI(title=APP_NAME)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            passhash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS stashes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    conn.commit()
    conn.close()


@app.on_event("startup")
def _startup():
    init_db()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def make_token(username: str) -> str:
    ts = str(int(time.time()))
    msg = f"{username}:{ts}".encode()
    sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).digest()
    raw = msg + b"." + sig
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_token(token: str) -> str:
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad)
        msg, sig = raw.split(b".", 1)
        exp_sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp_sig):
            raise ValueError("bad sig")
        username, _ts = msg.decode().split(":", 1)
        return username
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_user_id(username: str) -> Optional[int]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return int(row["id"]) if row else None


def token_from_cookie(request: Request) -> Optional[str]:
    return request.cookies.get("token")


def token_from_request(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return token_from_cookie(request)


def auth_ctx(request: Request) -> dict:
    token = token_from_cookie(request)
    logged_in = False
    username = None
    if token:
        try:
            username = parse_token(token)
            logged_in = True
        except Exception:
            pass
    return {"logged_in": logged_in, "username": username}


def tpl(request: Request, name: str, **ctx):
    base = {"request": request, "app_name": APP_NAME}
    base.update(auth_ctx(request))
    base.update(ctx)
    return templates.TemplateResponse(name, base)


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=3, max_length=64)


class LoginIn(BaseModel):
    username: str
    password: str


class StashIn(BaseModel):
    title: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=1, max_length=4096)


class StashOut(BaseModel):
    id: int
    title: str
    content: str
    created_at: int


@app.get("/health")
def health():
    return {"ok": True, "service": APP_NAME}


@app.get("/leaderboard", response_class=HTMLResponse)
def page_leaderboard(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username as username,
               COUNT(s.id) as stash_count
        FROM users u
        LEFT JOIN stashes s ON s.user_id = u.id
        GROUP BY u.id
        ORDER BY stash_count DESC, u.username ASC
        LIMIT 50
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return tpl(request, "leaderboard.html", rows=rows)


@app.get("/api/leaderboard")
def api_leaderboard():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username as username,
               COUNT(s.id) as stash_count
        FROM users u
        LEFT JOIN stashes s ON s.user_id = u.id
        GROUP BY u.id
        ORDER BY stash_count DESC, u.username ASC
        LIMIT 50
    """)
    rows = cur.fetchall()
    conn.close()
    return {
        "ok": True,
        "rows": [{"username": r["username"], "stash_count": int(r["stash_count"])} for r in rows]
    }

@app.post("/api/register")
def api_register(inp: RegisterIn):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, passhash, created_at) VALUES(?,?,?)",
            (inp.username, sha256_hex(inp.password), int(time.time()))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username exists")
    finally:
        conn.close()
    return {"ok": True}


@app.post("/api/login")
def api_login(inp: LoginIn):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT passhash FROM users WHERE username=?", (inp.username,))
    row = cur.fetchone()
    conn.close()

    if not row or row["passhash"] != sha256_hex(inp.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"token": make_token(inp.username)}


@app.post("/api/stash")
def api_create_stash(inp: StashIn, request: Request):
    token = token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    username = parse_token(token)
    uid = get_user_id(username)
    if uid is None:
        raise HTTPException(status_code=401, detail="No such user")

    conn = db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO stashes(user_id, title, content, created_at) VALUES(?,?,?,?)",
        (uid, inp.title, inp.content, int(time.time()))
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return {"ok": True, "id": sid}


@app.get("/api/stash", response_model=List[StashOut])
def api_list_stashes(request: Request):
    token = token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    username = parse_token(token)
    uid = get_user_id(username)
    if uid is None:
        raise HTTPException(status_code=401, detail="No such user")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, content, created_at FROM stashes WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (uid,)
    )
    rows = cur.fetchall()
    conn.close()
    return [StashOut(**dict(r)) for r in rows]

@app.get("/", response_class=HTMLResponse)
def page_index(request: Request):
    return tpl(request, "index.html")


@app.get("/register", response_class=HTMLResponse)
def page_register(request: Request):
    return tpl(request, "register.html", error=None)


@app.post("/register")
def do_register(username: str = Form(...), password: str = Form(...)):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, passhash, created_at) VALUES(?,?,?)",
            (username, sha256_hex(password), int(time.time()))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Username exists")
    conn.close()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def page_login(request: Request):
    return tpl(request, "login.html", error=None)


@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT passhash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row or row["passhash"] != sha256_hex(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = make_token(username)
    resp = RedirectResponse(url="/mili", status_code=303)
    resp.set_cookie("token", token, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie("token")
    return resp


@app.get("/mili", response_class=HTMLResponse)
def page_mili(request: Request):
    token = token_from_cookie(request)
    if not token:
        return RedirectResponse(url="/login", status_code=303)

    try:
        username = parse_token(token)
    except Exception:
        return RedirectResponse(url="/login", status_code=303)

    uid = get_user_id(username)
    if uid is None:
        return RedirectResponse(url="/login", status_code=303)

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, content, created_at FROM stashes WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (uid,)
    )
    rows = cur.fetchall()
    conn.close()

    stashes = [dict(r) for r in rows]
    return tpl(request, "mili.html", stashes=stashes)


@app.post("/stash/create")
def page_create_stash(request: Request, title: str = Form(...), content: str = Form(...)):
    token = token_from_cookie(request)
    if not token:
        return RedirectResponse(url="/login", status_code=303)

    try:
        username = parse_token(token)
    except Exception:
        return RedirectResponse(url="/login", status_code=303)

    uid = get_user_id(username)
    if uid is None:
        return RedirectResponse(url="/login", status_code=303)

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO stashes(user_id, title, content, created_at) VALUES(?,?,?,?)",
        (uid, title, content, int(time.time()))
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/mili", status_code=303)

@app.get("/public/{username}", response_class=HTMLResponse)
def public_view(username: str, request: Request):
    uid = get_user_id(username)
    
    if uid is None:
        raise HTTPException(status_code=404, detail="User not found")

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT title, content, created_at
        FROM stashes
        WHERE user_id=?
        ORDER BY id DESC
    """, (uid,))
    
    rows = cur.fetchall()
    conn.close()

    stashes = [dict(r) for r in rows]
    return tpl(request, "public.html",
               owner_name=username,
               stashes=stashes)