"""Эмулятор Bot API мессенджера MAX для локального тестирования бота.

Реализует минимум, который использует бот: /me, /updates (long polling),
POST и PUT /messages, /answers, /chats/{id}.

Дополнительно поднимает служебные ручки, которых нет в настоящем MAX:
  POST /_inject  - положить событие в очередь /updates
  GET  /_state   - выгрузить все отправленные сообщения, правки и ответы
  POST /_reset   - очистить состояние

Запуск: python3 tests/fake_max.py [порт]
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = "TEST-MAX-TOKEN"

LOCK = threading.Lock()
STATE = {
    "messages": [],   # отправленные сообщения
    "edits": [],      # правки сообщений
    "answers": [],    # ответы на callback
    "queue": [],      # события, ожидающие выдачи в /updates
    "marker": 1000,   # курсор событий
    "markers_seen": [],  # какие marker присылал бот
    "seq": 0,
}


def _next_mid():
    STATE["seq"] += 1
    return "mid.test{0}".format(STATE["seq"]), STATE["seq"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[max] " + fmt % args, flush=True)

    def _reply(self, code, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            return {}

    def _check_token(self, query):
        # настоящий MAX больше не принимает access_token в query - только Bearer в заголовке
        if query.get("access_token"):
            self._reply(401, {"code": "verify.token",
                              "message": "Query parameter access_token is deprecated, "
                                         "use Authorization header"})
            return False
        auth = self.headers.get("Authorization") or ""
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
        if token != TOKEN:
            self._reply(401, {"code": "verify.token", "message": "Invalid access_token"})
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/_state":
            with LOCK:
                return self._reply(200, {k: v for k, v in STATE.items() if k != "queue"})

        if not self._check_token(query):
            return

        if url.path == "/me":
            return self._reply(200, {
                "user_id": 1, "first_name": "SIEM bot", "name": "SIEM bot",
                "username": "siem_test_bot", "is_bot": True,
                "last_activity_time": int(time.time() * 1000),
            })

        if url.path == "/updates":
            marker = (query.get("marker") or [None])[0]
            timeout = int((query.get("timeout") or [30])[0])
            with LOCK:
                STATE["markers_seen"].append(marker)
            # long polling: держим соединение, пока не появятся события
            deadline = time.time() + min(timeout, 30)
            while time.time() < deadline:
                with LOCK:
                    if STATE["queue"]:
                        updates = STATE["queue"]
                        STATE["queue"] = []
                        STATE["marker"] += len(updates)
                        return self._reply(200, {"updates": updates, "marker": STATE["marker"]})
                time.sleep(0.1)
            with LOCK:
                return self._reply(200, {"updates": [], "marker": STATE["marker"]})

        if url.path.startswith("/chats/"):
            chat_id = url.path.rsplit("/", 1)[1]
            return self._reply(200, {"chat_id": int(chat_id), "type": "chat",
                                     "status": "active", "title": "SOC чат"})

        return self._reply(404, {"code": "not.found", "message": url.path})

    def do_POST(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        body = self._body()

        if url.path == "/_inject":
            with LOCK:
                STATE["queue"].append(body)
            return self._reply(200, {"queued": len(STATE["queue"])})

        if url.path == "/_reset":
            with LOCK:
                STATE.update({"messages": [], "edits": [], "answers": [], "queue": [],
                              "markers_seen": [], "seq": 0})
            return self._reply(200, {"ok": True})

        if not self._check_token(query):
            return

        if url.path == "/messages":
            chat_id = (query.get("chat_id") or [None])[0]
            user_id = (query.get("user_id") or [None])[0]
            if not chat_id and not user_id:
                return self._reply(400, {"code": "proto.payload",
                                         "message": "chat_id or user_id required"})
            with LOCK:
                mid, seq = _next_mid()
                record = {
                    "mid": mid,
                    "chat_id": int(chat_id) if chat_id else None,
                    "text": body.get("text"),
                    "attachments": body.get("attachments") or [],
                    "format": body.get("format"),
                    "notify": body.get("notify"),
                }
                STATE["messages"].append(record)
            print("[max] --> чат {0}: {1}".format(record["chat_id"],
                                                  (record["text"] or "<без текста>").replace("\n", " | ")[:120]),
                  flush=True)
            return self._reply(200, {"message": {
                "sender": {"user_id": 1, "first_name": "SIEM bot", "is_bot": True,
                           "last_activity_time": int(time.time() * 1000)},
                "recipient": {"chat_id": record["chat_id"], "chat_type": "dialog"},
                "timestamp": int(time.time() * 1000),
                "body": {"mid": mid, "seq": seq, "text": record["text"],
                         "attachments": record["attachments"]},
            }})

        if url.path == "/answers":
            callback_id = (query.get("callback_id") or [None])[0]
            if not callback_id:
                return self._reply(400, {"code": "proto.payload", "message": "callback_id required"})
            with LOCK:
                STATE["answers"].append({"callback_id": callback_id,
                                         "notification": body.get("notification")})
            print("[max] --> ответ на кнопку: {0}".format(body.get("notification")), flush=True)
            return self._reply(200, {"success": True})

        return self._reply(404, {"code": "not.found", "message": url.path})

    def do_PUT(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        body = self._body()

        if not self._check_token(query):
            return

        if url.path == "/messages":
            message_id = (query.get("message_id") or [None])[0]
            if not message_id:
                return self._reply(400, {"code": "proto.payload", "message": "message_id required"})
            with LOCK:
                STATE["edits"].append({"message_id": message_id, "text": body.get("text"),
                                       "attachments": body.get("attachments") or []})
            print("[max] --> правка {0}: {1}".format(
                message_id, (body.get("text") or "").replace("\n", " | ")[:120]), flush=True)
            return self._reply(200, {"success": True})

        return self._reply(404, {"code": "not.found", "message": url.path})


def serve(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("[max] эмулятор Bot API MAX слушает 127.0.0.1:{0}".format(port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
