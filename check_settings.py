"""Проверка настроек перед первым запуском бота.

Скрипт по очереди проверяет связь с MAX и с SIEM и подсказывает, что поправить.
Заодно показывает chat_id тех, кто уже написал боту - его нужно вписать
в параметр max_admin_chat_id.

Запуск:
    python3 check_settings.py

Бот в это время должен быть остановлен, иначе он разберет события раньше.
"""

import sys

import requests

import settings

requests.packages.urllib3.disable_warnings()

PLACEHOLDERS = {
    "max_bot_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "base_url": "https://siem.local",
    "username": "siemlogin",
    "client_secret": "cccccccc-dddd-3333-4444-eeeeeeeeeeee",
    "max_admin_chat_id": 123456789,
}

OK = "[ OK ]"
BAD = "[ !! ]"
INFO = "[ -- ]"

problems = []


def fail(text, hint=None):
    problems.append(text)
    print("{0} {1}".format(BAD, text))
    if hint:
        print("       -> {0}".format(hint))


def good(text):
    print("{0} {1}".format(OK, text))


def info(text):
    print("{0} {1}".format(INFO, text))


def section(title):
    print("\n" + title)
    print("-" * len(title))


def check_placeholders():
    section("1. Заполнены ли настройки в settings.py")
    for name, placeholder in PLACEHOLDERS.items():
        value = getattr(settings, name, None)
        if value == placeholder:
            fail("{0} осталось значением по умолчанию".format(name),
                 "впишите свое значение в settings.py")
        elif value in (None, "", 0):
            fail("{0} не заполнен".format(name))
        else:
            shown = value if name not in ("max_bot_token", "client_secret") else "***скрыто***"
            good("{0} = {1}".format(name, shown))
    if settings.base_url.endswith("/"):
        fail("base_url заканчивается на /", "уберите последний символ /")
    if settings.max_api_url.endswith("/"):
        fail("max_api_url заканчивается на /", "уберите последний символ /")
    if settings.max_updates_timeout > 90:
        fail("max_updates_timeout больше 90", "MAX не держит соединение дольше 90 секунд")


def _max_headers():
    # MAX ждет токен в заголовке Authorization БЕЗ префикса Bearer
    return {"Authorization": settings.max_bot_token}


def check_max():
    section("2. Связь с MAX")
    try:
        response = requests.get(
            settings.max_api_url + "/me",
            headers=_max_headers(),
            timeout=15,
            proxies=settings.max_proxys,
            verify=settings.max_verify_ssl,
        )
    except requests.exceptions.SSLError as ex:
        fail("ошибка SSL при обращении к MAX: {0}".format(ex),
             "проверьте max_api_url или временно поставьте max_verify_ssl = False")
        return None
    except requests.exceptions.ProxyError as ex:
        hint = "проверьте max_proxys в settings.py" if settings.max_proxys else \
            "max_proxys пуст, значит прокси навязан окружением - проверьте переменные " \
            "HTTP_PROXY и HTTPS_PROXY"
        fail("не работает прокси до MAX: {0}".format(ex), hint)
        return None
    except requests.exceptions.RequestException as ex:
        fail("нет связи с MAX ({0}): {1}".format(settings.max_api_url, ex),
             "проверьте доступность botapi.max.ru с этой машины и max_proxys")
        return None

    if response.status_code == 401:
        fail("MAX не принял токен (401)",
             "перевыпустите токен у @masterbot командой /mybots и впишите в max_bot_token")
        return None
    if response.status_code != 200:
        fail("MAX ответил кодом {0}: {1}".format(response.status_code, response.text[:200]))
        return None

    bot = response.json()
    good("токен принят, бот: {0} (@{1}), user_id {2}".format(
        bot.get("name") or bot.get("first_name"), bot.get("username"), bot.get("user_id")))
    return bot


def check_max_chats():
    section("3. Кто уже написал боту (отсюда берется max_admin_chat_id)")
    try:
        response = requests.get(
            settings.max_api_url + "/updates",
            params={"timeout": 3, "limit": 100},
            headers=_max_headers(),
            timeout=20,
            proxies=settings.max_proxys,
            verify=settings.max_verify_ssl,
        )
    except requests.exceptions.RequestException as ex:
        fail("не удалось получить события из MAX: {0}".format(ex))
        return

    if response.status_code != 200:
        fail("MAX ответил кодом {0} на /updates".format(response.status_code))
        return

    updates = response.json().get("updates") or []
    if not updates:
        info("событий нет. Напишите боту в MAX любое сообщение (или нажмите «Начать») "
             "и запустите проверку снова.")
        return

    found = {}
    for update in updates:
        chat_id = update.get("chat_id")
        who = update.get("user") or {}
        if update.get("update_type") in ("message_created", "message_callback"):
            message = update.get("message") or {}
            chat_id = (message.get("recipient") or {}).get("chat_id")
            who = (message.get("sender") or {}) or (update.get("callback") or {}).get("user") or {}
        if chat_id is None:
            continue
        name = who.get("username") or who.get("first_name") or "?"
        found[chat_id] = name

    for chat_id, name in found.items():
        mark = " <- сейчас указан как администратор" if chat_id == settings.max_admin_chat_id else ""
        print("       chat_id = {0}   ({1}){2}".format(chat_id, name, mark))
    if settings.max_admin_chat_id not in found:
        info("ни один из этих chat_id не совпадает с max_admin_chat_id = {0}. "
             "Если администратор - вы, впишите свой chat_id из списка выше.".format(
                 settings.max_admin_chat_id))
    else:
        good("max_admin_chat_id совпадает с одним из чатов выше")


def check_siem():
    section("4. Авторизация в SIEM")
    url = settings.base_url + ":3334/connect/token"
    payload = "username=" + settings.username + \
              "&password=" + settings.password + \
              "&client_id=" + settings.client_id + \
              "&client_secret=" + settings.client_secret + \
              "&grant_type=password" \
              "&response_type=code%20id_token" \
              "&scope=authorization%20offline_access%20mpx.api%20ptkb.api "
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Bearer undefined"},
    }
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False, timeout=30)
    except requests.exceptions.RequestException as ex:
        fail("нет связи с SIEM ({0}): {1}".format(url, ex),
             "проверьте base_url и что порт 3334 открыт с этой машины")
        return None

    if "invalid_username_or_password" in response.text:
        fail("SIEM не принял логин или пароль",
             "проверьте username и password; пароль со спецсимволами должен быть "
             "обернут в urllib.parse.quote()")
        return None
    if response.status_code != 200 or "access_token" not in response.text:
        fail("SIEM вернул код {0}: {1}".format(response.status_code, response.text[:300]),
             "чаще всего дело в client_id или client_secret")
        return None

    good("авторизация прошла, токен получен на {0} секунд".format(response.json().get("expires_in")))
    return response.json()["access_token"]


def check_incidents(token):
    section("5. Чтение инцидентов из SIEM")
    from datetime import datetime, timedelta
    url = settings.base_url + "/api/v2/incidents/"
    payload = {
        "offset": 0, "limit": 50,
        "groups": {"filterType": "no_filter"},
        "timeFrom": (datetime.now() - timedelta(days=1)).isoformat(),
        "timeTo": None,
        "filterTimeType": "creation",
        "filter": {"select": ["key", "name", "category", "type", "status", "created", "assigned"],
                   "orderby": [{"field": "created", "sortOrder": "descending"}]},
        "queryIds": ["all_incidents"],
    }
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(token)},
    }
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=60)
    except requests.exceptions.RequestException as ex:
        fail("не удалось запросить инциденты: {0}".format(ex))
        return

    if response.status_code == 401:
        fail("SIEM не принял токен при чтении инцидентов",
             "у пользователя может не быть прав на просмотр инцидентов")
        return
    if response.status_code != 200:
        fail("SIEM вернул код {0}: {1}".format(response.status_code, response.text[:300]))
        return

    incidents = response.json().get("incidents") or []
    good("инциденты читаются, за последние сутки их {0}".format(len(incidents)))
    for incident in incidents[:3]:
        print("       {0} | {1} | {2} | {3}".format(
            incident.get("key"), incident.get("severity"), incident.get("status"),
            incident.get("name")))
    if not incidents:
        info("инцидентов за сутки нет - это нормально, бот просто будет ждать новые")


def main():
    print("Проверка настроек бота оповещений MaxPatrol SIEM -> MAX")
    check_placeholders()
    if check_max():
        check_max_chats()
    token = check_siem()
    if token:
        check_incidents(token)

    print("\n" + "=" * 60)
    if problems:
        print("Найдено проблем: {0}".format(len(problems)))
        for problem in problems:
            print("  - {0}".format(problem))
        print("\nПоправьте settings.py и запустите проверку снова.")
        return 1
    print("Всё в порядке. Можно запускать:")
    print("  python3 mp-siem-max-bot-notification.py")
    print("\nПосле запуска отправьте боту /start, затем /accept {0} - "
          "без этого оповещения не придут даже администратору.".format(settings.max_admin_chat_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
