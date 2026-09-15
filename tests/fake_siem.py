"""Эмулятор API MaxPatrol SIEM 10 для локального тестирования бота.

Реализует ручки, которые использует бот:
  POST :3334/connect/token                        - выдача bearer-токена
  POST /api/v2/incidents/                         - список инцидентов с фильтром по timeFrom
  GET  /api/incidentsReadModel/incidents/{id}     - карточка инцидента
  GET  /api/incidents/{id}/events                 - события инцидента
  PUT  /api/incidents/{id}/transitions            - смена статуса

Служебные ручки, которых нет в настоящем SIEM:
  POST /_add_incident - добавить инцидент
  GET  /_state        - выгрузить инциденты и историю переходов
  POST /_reset        - очистить состояние

Токен выдается один раз, после выдачи старые запросы без него получают 401 -
это позволяет проверить, что бот сам переавторизуется.

Запуск: python3 tests/fake_siem.py
"""

import json
import re
import threading
import time
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = "TEST-SIEM-TOKEN"
API_PORT = 80
TOKEN_PORT = 3334

LOCK = threading.Lock()
STATE = {
    "incidents": [],
    "events": {},
    "transitions": [],
    "token_requests": 0,
    "incident_requests": 0,
}


def parse_ts(value):
    """Разобрать метку времени SIEM в datetime."""
    if not value:
        return None
    text = value.strip().rstrip("Z")
    # SIEM отдает до 7 знаков после запятой, datetime понимает максимум 6
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def add_incident(key=None, name=None, severity="High", inc_type="Attack",
                 status="New", created=None, events=None):
    incident_id = str(uuid.uuid4())
    created = created or datetime.utcnow().isoformat() + "0Z"
    incident = {
        "id": incident_id,
        "key": key or "INC-{0}".format(len(STATE["incidents"]) + 1),
        "name": name or "Подозрительная активность",
        "category": "Attack",
        "type": inc_type,
        "status": status,
        "severity": severity,
        "created": created,
        "assigned": None,
    }
    with LOCK:
        STATE["incidents"].append(incident)
        STATE["events"][incident_id] = events if events is not None else [
            {"date": datetime.utcnow().isoformat() + "0Z",
             "description": "Множественные неудачные попытки входа с 10.0.0.5"},
            {"date": datetime.utcnow().isoformat() + "0Z",
             "description": "Успешный вход пользователя admin с 10.0.0.5"},
        ]
    return incident


class TokenHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[siem:3334] " + fmt % args, flush=True)

    def do_POST(self):
        if urlparse(self.path).path != "/connect/token":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8")) if length else {}
        with LOCK:
            STATE["token_requests"] += 1
        if (form.get("grant_type") or [None])[0] != "password":
            body = {"error": "unsupported_grant_type"}
            code = 400
        elif not (form.get("username") or [None])[0]:
            body = {"error": "invalid_username_or_password"}
            code = 400
        else:
            body = {"access_token": TOKEN, "expires_in": 86400,
                    "refresh_token": "TEST-REFRESH", "token_type": "Bearer"}
            code = 200
            print("[siem:3334] выдан bearer-токен пользователю {0}".format(
                form.get("username")[0]), flush=True)
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[siem:80] " + fmt % args, flush=True)

    def _reply(self, code, body):
        raw = b"" if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            return {}

    def _authorized(self):
        if self.headers.get("Authorization") != "Bearer {0}".format(TOKEN):
            self._reply(401, {"error": "Unauthorised"})
            return False
        return True

    def _find(self, incident_id):
        with LOCK:
            for inc in STATE["incidents"]:
                if inc["id"] == incident_id:
                    return inc
        return None

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/_state":
            with LOCK:
                return self._reply(200, STATE)

        if not self._authorized():
            return

        match = re.match(r"^/api/incidents/([^/]+)/events$", path)
        if match:
            with LOCK:
                return self._reply(200, STATE["events"].get(match.group(1), []))

        match = re.match(r"^/api/incidentsReadModel/incidents/([^/]+)$", path)
        if match:
            incident = self._find(match.group(1))
            if incident is None:
                return self._reply(404, {"error": "not found"})
            return self._reply(200, incident)

        return self._reply(404, {"error": path})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/_add_incident":
            incident = add_incident(**body)
            print("[siem:80] добавлен инцидент {0} ({1})".format(incident["key"], incident["id"]), flush=True)
            return self._reply(200, incident)

        if path == "/_reset":
            with LOCK:
                STATE.update({"incidents": [], "events": {}, "transitions": [],
                              "token_requests": 0, "incident_requests": 0})
            return self._reply(200, {"ok": True})

        if not self._authorized():
            return

        if path == "/api/v2/incidents/":
            with LOCK:
                STATE["incident_requests"] += 1
            time_from = parse_ts(body.get("timeFrom"))
            with LOCK:
                found = []
                for inc in STATE["incidents"]:
                    created = parse_ts(inc["created"])
                    if time_from is None or (created is not None and created >= time_from):
                        found.append(inc)
            # SIEM отдает инциденты от новых к старым
            found.sort(key=lambda i: i["created"], reverse=True)
            return self._reply(200, {"incidents": found, "totalItems": len(found)})

        return self._reply(404, {"error": path})

    def do_PUT(self):
        path = urlparse(self.path).path
        body = self._body()

        if not self._authorized():
            return

        match = re.match(r"^/api/incidents/([^/]+)/transitions$", path)
        if match:
            incident = self._find(match.group(1))
            if incident is None:
                return self._reply(404, {"error": "not found"})
            with LOCK:
                incident["status"] = body.get("id")
                STATE["transitions"].append({
                    "incident_id": incident["id"],
                    "key": incident["key"],
                    "status": body.get("id"),
                    "measures": body.get("measures"),
                    "message": body.get("message"),
                })
            print("[siem:80] инцидент {0} переведен в статус {1}: {2}".format(
                incident["key"], body.get("id"), body.get("message")), flush=True)
            return self._reply(204, None)

        return self._reply(404, {"error": path})


def serve():
    api = ThreadingHTTPServer(("127.0.0.1", API_PORT), ApiHandler)
    token = ThreadingHTTPServer(("127.0.0.1", TOKEN_PORT), TokenHandler)
    print("[siem] эмулятор SIEM слушает 127.0.0.1:{0} (api) и 127.0.0.1:{1} (token)".format(
        API_PORT, TOKEN_PORT), flush=True)
    threading.Thread(target=token.serve_forever, daemon=True).start()
    api.serve_forever()


if __name__ == "__main__":
    serve()
