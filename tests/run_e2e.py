"""Сквозной тест бота против эмуляторов MAX и SIEM.

Тест не правит код бота: рядом создается временный каталог с копией скриптов
и подменённым settings.py, туда же кладется чистая БД.

Запуск из корня проекта:
    python3 tests/run_e2e.py

Требует свободные порты 80, 3334 (эмулятор SIEM) и 8765 (эмулятор MAX).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
TESTS = os.path.join(ROOT, "tests")
MAX_URL = "http://127.0.0.1:8765"
SIEM_URL = "http://127.0.0.1"
MAX_TOKEN = "TEST-MAX-TOKEN"
ADMIN = 111
USER = 777
USER2 = 888  # второй получатель: на нем проверяем, что отметка о действии видна всем

BOT_SCRIPT = "mp-siem-max-bot-notification.py"
COPY_FILES = [BOT_SCRIPT, "max_api.py", "db.py", "db_querys.py", "pretty_log.py"]

# Шаблон намеренно содержит только параметры первой версии бота: так тест заодно
# проверяет, что новый код работает со старым settings.py, который пользователь
# правил руками и который не обновляется через git pull.
SETTINGS = '''
from datetime import timedelta
import urllib.parse

dbFileName = r"{db}"
pause_time = 1
time_zone = timedelta(hours=3)
username = "siemlogin"
password = urllib.parse.quote("SI3M-P@$$w0rd")
client_id = "mpx"
client_secret = "test-secret"
base_url = "{siem}"

max_api_url = "{max}"
max_bot_token = "{token}"
max_updates_timeout = 2
max_updates_limit = 100
max_admin_chat_id = {admin}
max_proxys = {{}}
max_verify_ssl = False
max_message_length = 4000
max_events_count = 5

default_header = {{"User-Agent": "python-max-bot-test", "Accept": "*/*"}}
ping_sticker_code = ""
'''

RESULTS = []


def check(name, condition, detail=""):
    detail = "" if detail == "" or detail is None else str(detail)
    RESULTS.append((bool(condition), name, detail))
    mark = "OK  " if condition else "FAIL"
    print("  [{0}] {1}{2}".format(mark, name, (" - " + detail) if detail else ""), flush=True)
    return bool(condition)


def post(url, payload=None):
    data = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def get(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def max_state():
    return get(MAX_URL + "/_state")


def siem_state():
    return get(SIEM_URL + "/_state")


def inject(update):
    return post(MAX_URL + "/_inject", update)


def wait_for(description, predicate, timeout=25, interval=0.4):
    """Ждать выполнения условия, возвращает результат предиката либо None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = predicate()
        except (urllib.error.URLError, ConnectionError):
            value = None
        if value:
            return value
        time.sleep(interval)
    print("  (!) таймаут ожидания: {0}".format(description), flush=True)
    return None


def messages_to(state, chat_id):
    return [m for m in state["messages"] if m["chat_id"] == chat_id]


def find_message(state, chat_id, needle):
    for message in messages_to(state, chat_id):
        if needle in (message["text"] or ""):
            return message
    return None


def buttons_of(message):
    result = []
    for attachment in message.get("attachments") or []:
        if attachment.get("type") == "inline_keyboard":
            for row in attachment["payload"]["buttons"]:
                result.extend(row)
    return result


def callback_update(payload, chat_id, user_id, mid, username=None, first_name="Тест"):
    """Собрать событие message_callback в формате MAX."""
    return {
        "update_type": "message_callback",
        "timestamp": int(time.time() * 1000),
        "callback": {
            "timestamp": int(time.time() * 1000),
            "callback_id": "cb-{0}".format(int(time.time() * 1000)),
            "payload": payload,
            "user": {"user_id": user_id, "first_name": first_name, "username": username,
                     "is_bot": False, "last_activity_time": int(time.time() * 1000)},
        },
        "message": {
            "sender": {"user_id": 1, "first_name": "SIEM bot", "is_bot": True,
                       "last_activity_time": int(time.time() * 1000)},
            "recipient": {"chat_id": chat_id, "chat_type": "dialog"},
            "timestamp": int(time.time() * 1000),
            "body": {"mid": mid, "seq": 1, "text": "", "attachments": []},
        },
    }


def message_update(text, chat_id, user_id, username=None, first_name="Тест"):
    """Собрать событие message_created в формате MAX."""
    return {
        "update_type": "message_created",
        "timestamp": int(time.time() * 1000),
        "message": {
            "sender": {"user_id": user_id, "first_name": first_name, "username": username,
                       "is_bot": False, "last_activity_time": int(time.time() * 1000)},
            "recipient": {"chat_id": chat_id, "chat_type": "dialog"},
            "timestamp": int(time.time() * 1000),
            "body": {"mid": "mid.in{0}".format(int(time.time() * 1000)), "seq": 1, "text": text},
        },
    }


def main():
    workdir = tempfile.mkdtemp(prefix="siem-max-bot-")
    for name in COPY_FILES:
        shutil.copy(os.path.join(ROOT, name), os.path.join(workdir, name))
    with open(os.path.join(workdir, "settings.py"), "w", encoding="utf-8") as handle:
        handle.write(SETTINGS.format(db=os.path.join(workdir, "bot.db"), siem=SIEM_URL,
                                     max=MAX_URL, token=MAX_TOKEN, admin=ADMIN))

    processes = []
    logs = {}
    try:
        for name, args in (("siem", [sys.executable, os.path.join(TESTS, "fake_siem.py")]),
                           ("max", [sys.executable, os.path.join(TESTS, "fake_max.py"), "8765"])):
            log = open(os.path.join(workdir, name + ".log"), "w+", encoding="utf-8")
            logs[name] = log
            processes.append(subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT))

        if not wait_for("эмуляторы поднялись", lambda: max_state() is not None and siem_state() is not None,
                        timeout=15):
            raise RuntimeError("эмуляторы не запустились, см. логи в " + workdir)
        print("Эмуляторы MAX и SIEM запущены.\n", flush=True)

        bot_log = open(os.path.join(workdir, "bot.log"), "w+", encoding="utf-8")
        logs["bot"] = bot_log
        bot = subprocess.Popen([sys.executable, BOT_SCRIPT], cwd=workdir,
                               stdout=bot_log, stderr=subprocess.STDOUT)
        processes.append(bot)

        # 1. Старт: бот проверяет токен MAX, авторизуется в SIEM и пишет администратору
        print("1. Запуск бота", flush=True)
        state = wait_for("приветствие администратору",
                         lambda: find_message(max_state(), ADMIN, "Бот запущен"))
        check("бот сообщил администратору о запуске", state is not None)
        check("бот авторизовался в SIEM по 401", wait_for(
            "запрос токена", lambda: siem_state()["token_requests"] >= 1) is not None)
        check("бот опрашивает инциденты", wait_for(
            "запрос инцидентов", lambda: siem_state()["incident_requests"] >= 1) is not None)
        check("бот вернул marker в следующем запросе /updates", wait_for(
            "marker", lambda: any(m is not None for m in max_state()["markers_seen"])) is not None)

        # 2. Новый пользователь нажал "Начать" - администратор получает карточку с кнопками
        print("\n2. Пользователь нажал «Начать» (bot_started)", flush=True)
        inject({"update_type": "bot_started", "timestamp": int(time.time() * 1000), "chat_id": USER,
                "user": {"user_id": USER, "first_name": "Иван", "username": "ivan",
                         "is_bot": False, "last_activity_time": int(time.time() * 1000)}})
        card = wait_for("карточка нового чата",
                        lambda: find_message(max_state(), ADMIN, "Обнаружен новый"))
        check("администратор получил запрос на доступ", card is not None,
              (card["text"].splitlines()[0] if card else ""))
        payloads = [b["payload"] for b in buttons_of(card)] if card else []
        check("в карточке три кнопки accept/ignore/ban",
              payloads == ["accept:{0}".format(USER), "ignore:{0}".format(USER), "ban:{0}".format(USER)],
              str(payloads))
        check("пользователь пока НЕ получает оповещений",
              len(messages_to(max_state(), USER)) == 0)

        # 3. Администратор нажимает "Разрешить"
        print("\n3. Администратор нажал «Разрешить»", flush=True)
        inject(callback_update("accept:{0}".format(USER), ADMIN, ADMIN, card["mid"], first_name="Админ"))
        check("бот ответил на нажатие кнопки", wait_for(
            "ответ на callback",
            lambda: [a for a in max_state()["answers"] if a["notification"] == "Доступ разрешен"]) is not None)
        check("карточка в чате администратора отредактирована", wait_for(
            "правка карточки",
            lambda: [e for e in max_state()["edits"] if e["message_id"] == card["mid"]]) is not None)
        check("пользователю пришло уведомление о доступе", wait_for(
            "уведомление о доступе",
            lambda: find_message(max_state(), USER, "Администратор открыл доступ")) is not None)

        # 3б. Второй получатель - нужен, чтобы проверить рассылку отметки о действии
        print("\n3б. Администратор добавляет второй чат командой", flush=True)
        inject(message_update("/accept {0}".format(USER2), ADMIN, ADMIN, first_name="Админ"))
        check("второй чат добавлен в рассылку", wait_for(
            "уведомление второму чату",
            lambda: find_message(max_state(), USER2, "Администратор открыл доступ")) is not None)

        # 4. В SIEM появился инцидент - он должен уйти в разрешенный чат
        print("\n4. В SIEM создан инцидент", flush=True)
        incident = post(SIEM_URL + "/_add_incident",
                        {"key": "INC-E2E-1", "name": "Брутфорс учетной записи", "severity": "High"})
        incident_message = wait_for("сообщение об инциденте",
                                    lambda: find_message(max_state(), USER, "INC-E2E-1"))
        check("инцидент доставлен в разрешенный чат", incident_message is not None)
        check("перед инцидентами есть заголовок",
              find_message(max_state(), USER, "Новые инциденты") is not None)
        if incident_message:
            text = incident_message["text"]
            check("в тексте опасность с эмодзи", "Опасность: Высокая 🔴" in text)
            check("в тексте ссылка на инцидент", incident["id"] in text)
            check("в тексте события инцидента", "Множественные неудачные попытки входа" in text,
                  "событий в сообщении: {0}".format(text.count("Событие:")))
            check("время сдвинуто в часовой пояс из настроек", "Время: " in text,
                  [line for line in text.splitlines() if line.startswith("Время")][0])
            payloads = [b["payload"] for b in buttons_of(incident_message)]
            check("под новым инцидентом три кнопки",
                  payloads == ["check:{0}".format(incident["id"]),
                               "apprv:{0}".format(incident["id"]),
                               "close:{0}".format(incident["id"])], str(payloads))
        check("инцидент не задублировался при следующих опросах",
              wait_for("повторные опросы", lambda: siem_state()["incident_requests"] >= 4) is not None
              and len([m for m in messages_to(max_state(), USER) if "INC-E2E-1" in (m["text"] or "")]) == 1,
              "доставок: {0}".format(len([m for m in messages_to(max_state(), USER)
                                          if "INC-E2E-1" in (m["text"] or "")])))

        # 5. Пользователь подтверждает инцидент кнопкой
        print("\n5. Пользователь нажал «Подтвердить»", flush=True)
        inject(callback_update("apprv:{0}".format(incident["id"]), USER, USER,
                               incident_message["mid"], username="ivan", first_name="Иван"))
        transition = wait_for("переход инцидента",
                              lambda: siem_state()["transitions"] or None)
        check("SIEM получил смену статуса", transition is not None)
        if transition:
            first = transition[0]
            check("статус изменен на Approved", first["status"] == "Approved", first["status"])
            check("в комментарии SIEM указан пользователь MAX", "@ivan" in (first["message"] or ""),
                  first["message"])
            check("в мерах указан канал", "MAX" in (first["measures"] or ""), first["measures"])
        check("бот подтвердил нажатие пользователю", wait_for(
            "ответ на callback",
            lambda: [a for a in max_state()["answers"]
                     if a["notification"] == "Инцидент подтвержден"]) is not None)
        edit = wait_for("правка сообщения об инциденте",
                        lambda: ([e for e in max_state()["edits"]
                                  if e["message_id"] == incident_message["mid"]] or None))
        check("сообщение об инциденте обновлено", edit is not None)
        if edit:
            check("в обновленном тексте новый статус", "Статус: Approved" in edit[-1]["text"],
                  [line for line in edit[-1]["text"].splitlines() if line.startswith("Статус")])
            check("в сообщении видно, кто подтвердил", "▶️ Подтвердил: @ivan" in edit[-1]["text"],
                  [line for line in edit[-1]["text"].splitlines() if "Подтвердил" in line])
            payloads = [b["payload"] for b in buttons_of(edit[-1])]
            check("у подтвержденного инцидента осталась одна кнопка",
                  payloads == ["check:{0}".format(incident["id"])], str(payloads))

        # отметку должны увидеть и те, кто кнопку не нажимал
        message_user2 = find_message(max_state(), USER2, "INC-E2E-1")
        check("инцидент уходил и во второй чат", message_user2 is not None)
        if message_user2:
            edit2 = wait_for("правка сообщения во втором чате",
                             lambda: ([e for e in max_state()["edits"]
                                       if e["message_id"] == message_user2["mid"]] or None))
            check("во втором чате сообщение тоже обновлено", edit2 is not None)
            if edit2:
                check("второй чат видит, кто подтвердил",
                      "▶️ Подтвердил: @ivan" in edit2[-1]["text"],
                      [line for line in edit2[-1]["text"].splitlines() if "Подтвердил" in line])
                check("второй чат видит новый статус", "Статус: Approved" in edit2[-1]["text"])
                # у остальных дежурных кнопки действий должны пропасть,
                # чтобы никто не пытался подтвердить или закрыть повторно
                payloads2 = [b["payload"] for b in buttons_of(edit2[-1])]
                check("во втором чате кнопки Подтвердить и Закрыть исчезли",
                      payloads2 == ["check:{0}".format(incident["id"])], str(payloads2))
                texts2 = [b["text"] for b in buttons_of(edit2[-1])]
                check("во втором чате осталась только кнопка обновления",
                      all("Подтвердить" not in t and "Закрыть" not in t for t in texts2), str(texts2))

        # 5б. Второй дежурный нажимает кнопку по уже подтвержденному инциденту.
        # Так бывает, если он успел нажать до того, как у него перерисовалось сообщение.
        print("\n5б. Повторное нажатие по уже подтвержденному инциденту", flush=True)
        transitions_before = len(siem_state()["transitions"])
        inject(callback_update("apprv:{0}".format(incident["id"]), USER2, USER2,
                               message_user2["mid"] if message_user2 else incident_message["mid"],
                               username="petr", first_name="Петр"))
        late = wait_for("ответ на повторное нажатие",
                        lambda: ([a for a in max_state()["answers"]
                                  if (a["notification"] or "").startswith("Инцидент уже")] or None))
        check("бот объясняет, что инцидент уже подтвержден", late is not None,
              late[-1]["notification"] if late else "")
        if late:
            check("в ответе указан тот, кто нажал первым", "@ivan" in late[-1]["notification"],
                  late[-1]["notification"])
        check("повторный переход в SIEM не записан",
              len(siem_state()["transitions"]) == transitions_before,
              "переходов было {0}, стало {1}".format(transitions_before,
                                                     len(siem_state()["transitions"])))
        check("бот не приписал второе действие в историю", wait_for(
            "история действий",
            lambda: ([e for e in max_state()["edits"]
                      if e["message_id"] == incident_message["mid"]] or None)) is not None
              and [e for e in max_state()["edits"]
                   if e["message_id"] == incident_message["mid"]][-1]["text"].count("Подтвердил") == 1)

        # 6. Команды
        print("\n6. Команды бота", flush=True)
        inject(message_update("/ping", USER, USER, username="ivan"))
        check("/ping из разрешенного чата отвечает", wait_for(
            "ответ на ping", lambda: find_message(max_state(), USER, "Бот на связи")) is not None)
        inject(message_update("/accepted", ADMIN, ADMIN, first_name="Админ"))
        check("/accepted показывает список чатов", wait_for(
            "список чатов", lambda: find_message(max_state(), ADMIN, "Список чатов")) is not None)
        inject(message_update("/help", ADMIN, ADMIN, first_name="Админ"))
        check("/help отвечает администратору", wait_for(
            "справка", lambda: find_message(max_state(), ADMIN, "/debug - получить последние логи")) is not None)
        inject(message_update("/debug", ADMIN, ADMIN, first_name="Админ"))
        check("/debug показывает состояние", wait_for(
            "debug", lambda: find_message(max_state(), ADMIN, "last_marker =")) is not None)

        # 7. Слитная команда, как в Telegram-версии, и блокировка чата
        print("\n7. Блокировка чата и слитные команды", flush=True)
        inject(message_update("/ban999", ADMIN, ADMIN, first_name="Админ"))
        check("слитная команда /ban999 разобрана", wait_for(
            "бан", lambda: find_message(max_state(), ADMIN, "Вы заблокировали чат с id 999")) is not None)
        before = len(max_state()["messages"])
        inject(message_update("/start", 999, 999, first_name="Злоумышленник"))
        time.sleep(6)
        check("события заблокированного чата игнорируются",
              len(max_state()["messages"]) == before,
              "новых сообщений: {0}".format(len(max_state()["messages"]) - before))
        inject(message_update("/banned", ADMIN, ADMIN, first_name="Админ"))
        check("/banned показывает список", wait_for(
            "список бана", lambda: find_message(max_state(), ADMIN, "Список заблокированных чатов: [999]")) is not None)

        # 8. Второй инцидент и кнопка "Закрыть"
        print("\n8. Второй инцидент и кнопка «Закрыть»", flush=True)
        incident2 = post(SIEM_URL + "/_add_incident",
                         {"key": "INC-E2E-2", "name": "Вредоносное ПО", "severity": "Medium"})
        message2 = wait_for("второй инцидент",
                            lambda: find_message(max_state(), USER, "INC-E2E-2"))
        check("второй инцидент доставлен", message2 is not None)
        if message2:
            check("средняя опасность отмечена оранжевым", "Опасность: Средняя 🟠" in message2["text"])
            inject(callback_update("close:{0}".format(incident2["id"]), USER, USER,
                                   message2["mid"], username="ivan", first_name="Иван"))
            closed = wait_for("закрытие инцидента",
                              lambda: ([t for t in siem_state()["transitions"]
                                        if t["key"] == "INC-E2E-2"] or None))
            check("инцидент закрыт в SIEM", closed is not None and closed[0]["status"] == "Closed",
                  closed[0]["status"] if closed else "")

        # 8б. SIEM отвечает ошибкой - бот обязан пережить это и восстановиться
        print("\n8б. Сбой SIEM (503 без поля incidents)", flush=True)
        post(SIEM_URL + "/_fail_incidents", {"count": 3})
        requests_before = siem_state()["incident_requests"]
        check("бот пережил ошибку SIEM и продолжает опрашивать", wait_for(
            "опросы после сбоя",
            lambda: siem_state()["incident_requests"] >= requests_before + 5, timeout=40) is not None)
        check("процесс бота не упал", bot.poll() is None)
        incident3 = post(SIEM_URL + "/_add_incident",
                         {"key": "INC-E2E-3", "name": "После сбоя", "severity": "Low"})
        check("после восстановления SIEM инциденты снова доставляются", wait_for(
            "инцидент после сбоя",
            lambda: find_message(max_state(), USER, "INC-E2E-3"), timeout=40) is not None)

        # 9. Перезапуск: состояние живет в БД, повторной рассылки быть не должно
        print("\n9. Перезапуск бота", flush=True)
        delivered_before = len([m for m in messages_to(max_state(), USER) if "INC-E2E" in (m["text"] or "")])
        bot.terminate()
        bot.wait(timeout=10)
        processes.remove(bot)
        bot = subprocess.Popen([sys.executable, BOT_SCRIPT], cwd=workdir,
                               stdout=bot_log, stderr=subprocess.STDOUT)
        processes.append(bot)
        check("бот поднялся после перезапуска", wait_for(
            "второе приветствие",
            lambda: len([m for m in messages_to(max_state(), ADMIN)
                         if "Бот запущен" in (m["text"] or "")]) >= 2) is not None)
        # даем несколько циклов опроса SIEM
        requests_before = siem_state()["incident_requests"]
        wait_for("опросы после перезапуска",
                 lambda: siem_state()["incident_requests"] >= requests_before + 3, timeout=30)
        delivered_after = len([m for m in messages_to(max_state(), USER) if "INC-E2E" in (m["text"] or "")])
        check("старые инциденты не разосланы заново", delivered_after == delivered_before,
              "до перезапуска {0}, после {1}".format(delivered_before, delivered_after))
        inject(message_update("/accepted", ADMIN, ADMIN, first_name="Админ"))
        check("список разрешенных чатов сохранился в БД", wait_for(
            "список после перезапуска",
            lambda: [m for m in messages_to(max_state(), ADMIN)
                     if "Список чатов" in (m["text"] or "") and str(USER) in m["text"]]) is not None)
        inject(message_update("/banned", ADMIN, ADMIN, first_name="Админ"))
        check("список заблокированных чатов сохранился в БД", wait_for(
            "бан после перезапуска",
            lambda: [m for m in messages_to(max_state(), ADMIN)
                     if "Список заблокированных чатов: [999]" in (m["text"] or "")]) is not None)

        # 10. Токен MAX проверяется через заголовок Authorization без префикса Bearer
        print("\n10. Авторизация в MAX", flush=True)
        try:
            request = urllib.request.Request(MAX_URL + "/me", headers={"Authorization": "WRONG"})
            urllib.request.urlopen(request, timeout=10)
            check("MAX отклоняет неверный токен", False, "эмулятор ответил 200")
        except urllib.error.HTTPError as error:
            check("MAX отклоняет неверный токен", error.code == 401, "код {0}".format(error.code))
        try:
            request = urllib.request.Request(MAX_URL + "/me",
                                             headers={"Authorization": "Bearer " + MAX_TOKEN})
            urllib.request.urlopen(request, timeout=10)
            check("MAX отклоняет токен с префиксом Bearer", False, "эмулятор ответил 200")
        except urllib.error.HTTPError as error:
            check("MAX отклоняет токен с префиксом Bearer", error.code == 401,
                  "код {0}".format(error.code))
        try:
            urllib.request.urlopen(MAX_URL + "/me?access_token=" + MAX_TOKEN, timeout=10)
            check("MAX отклоняет устаревший access_token в query", False, "эмулятор ответил 200")
        except urllib.error.HTTPError as error:
            check("MAX отклоняет устаревший access_token в query", error.code == 401,
                  "код {0}".format(error.code))

        check("бот жив и продолжает цикл", bot.poll() is None)

    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        for log in logs.values():
            log.flush()

        failed = [r for r in RESULTS if not r[0]]
        print("\n" + "=" * 70)
        print("ИТОГ: {0} из {1} проверок пройдено".format(len(RESULTS) - len(failed), len(RESULTS)))
        if failed:
            print("Не пройдено:")
            for _, name, detail in failed:
                print("  - {0}{1}".format(name, (" - " + detail) if detail else ""))
        print("Логи бота и эмуляторов: {0}".format(workdir))
        print("=" * 70)

    return 1 if [r for r in RESULTS if not r[0]] else 0


if __name__ == "__main__":
    sys.exit(main())
