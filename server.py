
import json
import sqlite3
import os
import ssl
from urllib.parse import urlparse, unquote
import pg8000.dbapi
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB = ROOT / "transport.db"
ENV_FILE = ROOT / ".env.local"

def neon_connect():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL missing")
    u = urlparse(url)
    return pg8000.dbapi.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=unquote(u.username or ""),
        password=unquote(u.password or ""),
        ssl_context=ssl.create_default_context()
    )


# AUTH_BACKEND_V1
import hashlib, hmac, secrets, time

SESSIONS = {}

# Basic login rate limiting: per client IP, temporary lockout.
LOGIN_ATTEMPTS = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 300

def login_is_limited(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS

def record_login_failure(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    LOGIN_ATTEMPTS[ip] = attempts

def clear_login_failures(ip):
    LOGIN_ATTEMPTS.pop(ip, None)

def load_admin_config():
    f = ROOT / ".admin.env"
    if not f.exists():
        raise RuntimeError("Admin configuration missing")
    for line in f.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

def check_password(password, salt, expected):
    try:
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                                n=2**14, r=8, p=1).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def find_admin(username, password):
    load_admin_config()
    for role, prefix in (("principal", "PRINCIPAL"),
                         ("secretary", "SECRETARY"),
                         ("admin", "ADMIN")):
        saved = os.environ.get(prefix + "_USERNAME", "")
        salt = os.environ.get(prefix + "_SALT", "")
        digest = os.environ.get(prefix + "_HASH", "")
        if saved and hmac.compare_digest(username, saved) and check_password(password, salt, digest):
            return role
    return None

def get_session(handler):
    for part in handler.headers.get("Cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "kce_session":
            data = SESSIONS.get(v)
            if data and data["expires"] > time.time():
                return v, data
            SESSIONS.pop(v, None)
    return None, None

def hash_student_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + salt.hex() + "$" + digest.hex()

def check_student_password(password, saved):
    try:
        scheme, salt, expected = saved.split("$", 2)
        return scheme == "scrypt" and check_password(password, salt, expected)
    except (ValueError, AttributeError):
        return False

class PortalHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)

        # Require an authenticated session for portal data APIs.
        protected_paths = {
            "/api/vehicles",
            "/api/buses",
            "/api/transport-buses",
        }
        if parsed.path in protected_paths:
            _, session = get_session(self)
            if not session:
                return self.send_json({
                    "success": False,
                    "error": "Login required"
                }, 401)



        if parsed.path == "/api/me":
            _, sess = get_session(self)
            if not sess:
                return self.send_json({"success": False, "authenticated": False}, 401)
            return self.send_json({"success": True, "authenticated": True,
                                   "username": sess["username"], "role": sess["role"]})

        if parsed.path == "/api/students":
            _, sess = get_session(self)
            if not sess:
                return self.send_json({"success": False, "error": "Login required"}, 401)
            if sess["role"] not in ("principal", "secretary", "admin"):
                return self.send_json({"success": False, "error": "Admin permission required"}, 403)
            try:
                con = neon_connect()
                try:
                    cur = con.cursor()
                    cur.execute("SELECT id, username, active, created_at FROM portal_users WHERE role = 'student' ORDER BY id")
                    rows = cur.fetchall()
                    cur.close()
                finally:
                    con.close()
                return self.send_json({"success": True, "students": [
                    {"id": r[0], "username": r[1], "active": r[2],
                     "created_at": r[3].isoformat() if r[3] else None} for r in rows
                ]})
            except Exception:
                return self.send_json({"success": False, "error": "Could not load student accounts"}, 503)

        if parsed.path == "/api/health":
            try:
                con = neon_connect()
                con.close()
                return self.send_json({"success": True, "database": "Neon PostgreSQL"})
            except Exception:
                return self.send_json({"success": False, "database": "Neon PostgreSQL", "error": "Database connection failed"}, 503)


        if parsed.path == "/api/transport-buses":
            with sqlite3.connect(DB) as con:
                con.row_factory = sqlite3.Row
                rows = con.execute("""
                    SELECT b.bus_number, b.starting_time,
                           p.place_name AS starting_place
                    FROM buses b
                    LEFT JOIN bus_starting_places p
                      ON p.bus_number = b.bus_number
                    ORDER BY CAST(b.bus_number AS INTEGER)
                """).fetchall()
            return self.send_json({
                "success": True,
                "buses": [dict(row) for row in rows]
            })


        if parsed.path == "/api/vehicles":
            try:
                con = neon_connect()
                try:
                    cur = con.cursor()
                    cur.execute("SELECT id, vehicle_label, starting_time FROM vehicles ORDER BY id")
                    vehicles = cur.fetchall()
                    output = []
                    for v in vehicles:
                        cur.execute(
                            "SELECT stop_name, stop_order, stop_count FROM vehicle_stops WHERE vehicle_id = %s ORDER BY stop_order",
                            (v[0],)
                        )
                        output.append({
                            "id": v[0],
                            "label": v[1],
                            "starting_time": v[2],
                            "stops": [
                                {"stop_name": st[0], "stop_order": st[1], "stop_count": st[2]}
                                for st in cur.fetchall()
                            ]
                        })
                    cur.close()
                finally:
                    con.close()
                return self.send_json({"success": True, "count": len(output), "vehicles": output})
            except Exception:
                return self.send_json({"success": False, "error": "Could not load vehicles from cloud database."}, 503)

        if parsed.path == "/api/buses":
            params = parse_qs(parsed.query)
            search = params.get("search", [""])[0].strip()

            with sqlite3.connect(DB) as con:
                con.row_factory = sqlite3.Row
                rows = con.execute("""
                    SELECT b.id, b.bus_number, b.starting_time,
                           s.stop_name, s.stop_order, s.stop_time
                    FROM buses b
                    LEFT JOIN bus_stops s ON s.bus_id = b.id
                    WHERE b.bus_number LIKE ?
                       OR s.stop_name LIKE ?
                    ORDER BY b.bus_number, s.stop_order
                """, (f"%{search}%", f"%{search}%")).fetchall()

            buses = {}
            for row in rows:
                bid = row["id"]
                if bid not in buses:
                    buses[bid] = {
                        "id": bid,
                        "bus_number": row["bus_number"],
                        "starting_time": row["starting_time"],
                        "stops": []
                    }
                if row["stop_name"] is not None:
                    buses[bid]["stops"].append({
                        "name": row["stop_name"],
                        "order": row["stop_order"],
                        "time": row["stop_time"]
                    })

            return self.send_json({
                "success": True,
                "count": len(buses),
                "buses": list(buses.values())
            })

        return super().do_GET()


    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/login", "/api/logout", "/api/students"):
            return self.send_json({"success": False, "error": "Not found"}, 404)

        if path == "/api/logout":
            token, _ = get_session(self)
            if token:
                SESSIONS.pop(token, None)
            self.send_response(200)
            self.send_header("Set-Cookie", "kce_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"success":true}')
            return

        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
            return self.send_json({"success": False, "error": "Invalid origin"}, 403)

        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 1 or n > 20000:
                raise ValueError()
            data = json.loads(self.rfile.read(n))
            if not isinstance(data, dict):
                raise ValueError()
        except Exception:
            return self.send_json({"success": False, "error": "Invalid JSON"}, 400)

        if path == "/api/login":
            client_ip = self.client_address[0]
            if login_is_limited(client_ip):
                self.send_header("Retry-After", str(LOGIN_LOCK_SECONDS))
                return self.send_json(
                    {"success": False, "error": "Too many login attempts. Try again in 5 minutes."},
                    429
                )
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            if not username or not password or len(username) > 150 or len(password) > 256:
                return self.send_json({"success": False, "error": "Enter username and password"}, 400)

            role = None
            try:
                role = find_admin(username, password)
            except Exception:
                pass

            if role is None:
                try:
                    con = neon_connect()
                    try:
                        cur = con.cursor()
                        cur.execute("SELECT password_hash, role, active FROM portal_users WHERE username = %s", (username,))
                        row = cur.fetchone()
                        cur.close()
                    finally:
                        con.close()
                    if row and row[2] and row[1] == "student" and check_student_password(password, row[0]):
                        role = "student"
                except Exception:
                    return self.send_json({"success": False, "error": "Login service unavailable"}, 503)

            if role is None:
                record_login_failure(client_ip)
                return self.send_json({"success": False, "error": "Invalid username or password"}, 401)

            clear_login_failures(client_ip)

            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {"username": username, "role": role, "expires": time.time() + 28800}
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie", f"kce_session={token}; Max-Age=28800; HttpOnly; SameSite=Strict; Path=/")
            response_body = json.dumps({"success": True, "username": username, "role": role}).encode()
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            return

        _, sess = get_session(self)
        if not sess or sess["role"] not in ("principal", "secretary", "admin"):
            return self.send_json({"success": False, "error": "Admin permission required"}, 403)

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not username or len(username) > 150 or len(password) < 8 or len(password) > 256:
            return self.send_json({"success": False, "error": "Student ID and password (8+ characters) required"}, 400)
        try:
            con = neon_connect()
            try:
                cur = con.cursor()
                cur.execute("INSERT INTO portal_users (username, password_hash, role, active) VALUES (%s, %s, 'student', TRUE)",
                            (username, hash_student_password(password)))
                con.commit()
                cur.close()
            finally:
                con.close()
            return self.send_json({"success": True, "message": "Student account created"})
        except Exception:
            return self.send_json({"success": False, "error": "Could not create account; ID may already exist"}, 400)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

if __name__ == "__main__":
    print("KINGS Student Smart Portal backend")
    print("Open: http://127.0.0.1:8080/index.html")
    print("API:   http://127.0.0.1:8080/api/health")
    print("Stop with Ctrl+C")
    ThreadingHTTPServer(("127.0.0.1", 8080), PortalHandler).serve_forever()
