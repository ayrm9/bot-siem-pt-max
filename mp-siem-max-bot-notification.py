import time
from datetime import datetime, timedelta

import requests

import db
import db_querys
import max_api
import pretty_log
import settings

# Включение логирования
logger = pretty_log.PrettyLog(prefix="Main", limit=10)
log = logger.logging

# Отключение предупреждений SSL в консоль
requests.packages.urllib3.disable_warnings()

# Переопределение кол-ва попыток для запросов по URL
requests.adapters.DEFAULT_RETRIES = 3

# Служебные переменные
bot_db_connect, bot_db_cursor = db.connection_init()  # инициализация подключения к БД бота
bearer_token = None  # хранит полученный токен для связи с SIEM
bearer_token_lifetime = None  # не используется
refresh_token = None  # хранит полученный refresh_token для обновления bearer_token
allowed_chats_ids = db.DbTable(db_connection=bot_db_connect,
                               db_cursor=bot_db_cursor,
                               db_query_append=db_querys.chat_allowed_insert,
                               db_query_get=db_querys.chat_allowed_get,
                               db_query_del=db_querys.chat_allowed_delete)
banned_chats_ids = db.DbTable(db_connection=bot_db_connect,
                              db_cursor=bot_db_cursor,
                              db_query_append=db_querys.chat_banned_insert,
                              db_query_get=db_querys.chat_banned_get,
                              db_query_del=db_querys.chat_banned_delete)

# хранит время последнего отправленного ботом инцидента
last_incident_time = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_incident_time_set,
                                   db_querys.last_incident_time_get)
# хранит marker последнего обработанного события из MAX
last_marker = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_marker_set, db_querys.last_marker_get)


# Авторизация
def siem_get_bearer_token():
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
        **{"Content-Type": "application/x-www-form-urlencoded",
           "Authorization": "Bearer undefined"}
    }
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    global bearer_token, refresh_token, bearer_token_lifetime
    if 'invalid_username_or_password' in response.text:
        log("Auth error: invalid_username_or_password")
        return 0
    if "access_token" in response.text:
        json_response = response.json()
        bearer_token = json_response["access_token"]
        bearer_token_lifetime = json_response["expires_in"]
        refresh_token = json_response["refresh_token"]
        log("Авторизация пройдена")
    return bearer_token


# Получение списка инцидентов
def siem_get_incidents():
    global last_incident_time
    # при первом запуске last_incident_time не установлен
    if not last_incident_time.get():
        today = datetime.now()
        last_1d = (today - timedelta(days=1)).isoformat()
        # используется заранее заданный отступ по дате (сутки)
        last_incident_time.set(last_1d)
    log("Пробую найти инциденты от {0}, текущий токен {1}".format(last_incident_time.get(), bearer_token))

    url = settings.base_url + "/api/v2/incidents/"
    # фильтр инцидентов
    payload = {
        "offset": 0,
        "limit": 50,
        "groups": {"filterType": "no_filter"},
        "timeFrom": last_incident_time.get(),
        "timeTo": None,
        "filterTimeType": "creation",
        "filter": {
            "select": ["key", "name", "category", "type", "status", "created", "assigned"],
            "orderby": [
                {
                    "field": "created",
                    "sortOrder": "descending"
                },
                {
                    "field": "status",
                    "sortOrder": "ascending"
                },
                {
                    "field": "severity",
                    "sortOrder": "descending"
                }
            ]
        },
        "queryIds": ["all_incidents"]
    }
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(bearer_token)}
    }

    response = requests.request("POST", url, json=payload, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()['incidents']


# Получить информацию по инциденту
def siem_get_incident_by_id(incident_id):
    url = settings.base_url + "/api/incidentsReadModel/incidents/" + str(incident_id)
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()


# Поиск событий по id инцидента
def siem_get_events_by_incident_id(incident_id):
    url = settings.base_url + "/api/incidents/" + incident_id + "/events"
    payload = ""
    headers = {
        **settings.default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False)
    return response.json()


# Изменить статус инцидента
def siem_set_incident_status(incident_id, status, measures=None, message=None):
    url = settings.base_url + "/api/incidents/" + incident_id + "/transitions"
    payload = {
        "id": status,
        "measures": measures,
        "message": message
    }
    headers = {
        **settings.default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    log("Попытка изменить инцидент, payload: {0}; header: {1}".format(payload, headers))
    response = requests.request(method="PUT", url=url, headers=headers, verify=False, json=payload)
    return response.status_code


# Превращение инцидента в строку
def incident_to_string(incident):
    try:
        # время обрезается до формата, который удается распарсить, добавляется поправка на наш часовой пояс
        inc_date = (datetime.fromisoformat(incident['created'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
        inc_id = incident['id']
        inc_key = incident['key']
        inc_severity = incident['severity']
        inc_type = incident['type']
        inc_name = incident['name']
        inc_status = incident['status']
        inc_link = f'{settings.base_url}/#/incident/incidents/view/{inc_id}'

        # к обозначению опасности добавляю цветной эмодзи для наглядности
        if inc_severity == "High":
            inc_severity = "Высокая 🔴"
        elif inc_severity == "Medium":
            inc_severity = "Средняя 🟠"
        elif inc_severity == "Low":
            inc_severity = "Низкая 🟡"

        # получение событий по инциденту
        events = siem_get_events_by_incident_id(incident_id=inc_id)
        events_str = "\nИнцидент без событий"
        # если есть события
        if len(events) > 0:
            events_str = "\nСобытия по инциденту: \n\n"
            ev_number = 0
            # парсинг событий в строку events_str
            for ev in events:
                ev_number += 1
                ev_date = (datetime.fromisoformat(ev['date'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
                ev_description = ev['description']
                ev_str = "Дата: {0}\nСобытие: {1}".format(ev_date, ev_description)
                events_str = events_str + ev_str + "\n\n"
                # если обработали нужное число событий - остановиться
                if ev_number == settings.max_events_count:
                    events_str = events_str + "И еще {0} событий.".format(len(events) - ev_number)
                    break
        result_string = f"{inc_key}\n" \
                        f"Время: {inc_date}\n" \
                        f"Опасность: {inc_severity}\n" \
                        f"Тип: {inc_type}\n" \
                        f"Имя: {inc_name}\n" \
                        f"Статус: {inc_status}\n" \
                        f"Ссылка на инцидент: {inc_link}" \
                        f"\n{events_str}"
        return result_string
    except Exception as ex_parse:
        log("Ошибка при парсинге инцидента: " + str(ex_parse))
        return "Не удалось распарсить инцидент"


# Генерация клавиатуры под инцидент
def generate_incident_keyboard(incident):
    inc_id = incident['id']
    if incident['status'] == "New":
        buttons = [[
            max_api.callback_button(text="🔄 Обновить", payload="check:" + inc_id),
            max_api.callback_button(text="▶️ Подтвердить", payload="apprv:" + inc_id,
                                   intent=max_api.INTENT_POSITIVE),
            max_api.callback_button(text="⏹ Закрыть", payload="close:" + inc_id,
                                   intent=max_api.INTENT_NEGATIVE),
        ]]
    else:
        buttons = [[
            max_api.callback_button(text="🔄 Обновить информацию", payload="check:" + inc_id),
        ]]
    return max_api.inline_keyboard(buttons)


# Генерация клавиатуры под запрос доступа для чата
def generate_chat_keyboard(chat_id):
    buttons = [
        [max_api.callback_button(text="✅ Разрешить", payload="accept:{0}".format(chat_id),
                                 intent=max_api.INTENT_POSITIVE)],
        [max_api.callback_button(text="⏹ Проигнорировать", payload="ignore:{0}".format(chat_id)),
         max_api.callback_button(text="⛔️ Заблокировать", payload="ban:{0}".format(chat_id),
                                 intent=max_api.INTENT_NEGATIVE)],
    ]
    return max_api.inline_keyboard(buttons)


# Добавить чат в список оповещаемых
def allow_chat(allow_chat_id):
    try:
        allow_chat_id = int(allow_chat_id)
    except (TypeError, ValueError):
        return False, "Не указан корректный id чата для добавления."
    if allow_chat_id in allowed_chats_ids.get():
        return False, f"Доступ уже был разрешен для чата {allow_chat_id}"
    if allowed_chats_ids.append(allow_chat_id):
        return True, None
    return False, "При добавлении значения в БД произошла ошибка. " \
                  "Значение добавлено во временную переменную до перезапуска."


# Заблокировать чат (не обрабатывать события из этого чата)
def ban_chat(ban_chat_id):
    try:
        ban_chat_id = int(ban_chat_id)
    except (TypeError, ValueError):
        return False, "Не указан корректный id чата для блокировки."
    if ban_chat_id in banned_chats_ids.get():
        return False, f"Доступ ранее уже был заблокирован для чата {ban_chat_id}"
    if banned_chats_ids.append(ban_chat_id):
        return True, None
    return False, "При добавлении значения в БД произошла ошибка. " \
                  "Значение добавлено во временную переменную до перезапуска."


# Разбор команды: возвращает (команда, аргумент)
# Поддерживаются варианты "/accept 123", "/accept123" и "/accept@botname 123"
def parse_command(text):
    body = text.strip().split(maxsplit=1)
    head = body[0]
    argument = body[1].strip() if len(body) > 1 else ""
    # MAX, как и Telegram, может добавить к команде имя бота
    if '@' in head:
        head = head.split('@', 1)[0]
    command = head
    # цифры, слитые с командой (например /accept123456789)
    for position, char in enumerate(head):
        if position > 0 and (char.isdigit() or char == '-'):
            command = head[:position]
            argument = head[position:] + argument
            break
    return command.lower(), argument


# Имя пользователя для логов и сообщений
def user_to_string(user):
    if not isinstance(user, dict):
        return str(user)
    if user.get("username"):
        return '@' + user["username"]
    if user.get("first_name"):
        return " ".join(filter(None, [user.get("first_name"), user.get("last_name")]))
    return str(user.get("user_id"))


# Текст справки для администратора
def help_message():
    return "/ping - проверка работоспособности бота\n" \
           "`/accept[id]` - вручную разрешить отправку оповещений об " \
           "инцидентах в чат по id (например `/accept 123456789`)\n" \
           "/accepted - отобразить список всех чатов, куда отправляются " \
           "оповещения об инцидентах\n" \
           "`/deny[id]` - перестать отправлять оповещения об инцидентах в " \
           "чат по id (например `/deny 123456789`)\n" \
           "`/ban[id]` - заблокировать чат по id: перестать обрабатывать " \
           "любые события с чатом, не оповещать администратора о нем " \
           "(например `/ban 123456789`)\n" \
           "`/unban[id]` - убрать чат из списка заблокированных " \
           "(например `/unban 123456789`)\n" \
           "/banned - отобразить список заблокированных чатов\n" \
           "/debug - получить последние логи\n"


# Обработка текстовых сообщений боту
def handle_message(message):
    chat_id = message.get("recipient", {}).get("chat_id")
    sender = message.get("sender", {})
    sender_id = sender.get("user_id")
    text = message.get("body", {}).get("text")
    if chat_id in banned_chats_ids or sender_id in banned_chats_ids:
        # игнорировать сообщение от заблокированных чатов
        log("Проигнорировано сообщение из заблокированного чата")
        return None
    if not text:
        log("Входящее сообщение без текста проигнорировано")
        return None
    username = user_to_string(sender)
    log("Входящее сообщение от {0} ({1}): {2}".format(username, chat_id, text))
    if not text.startswith('/'):
        return None

    command, argument = parse_command(text)
    is_admin = chat_id == settings.max_admin_chat_id

    if command == "/start":
        # чат нужно предложить администратору
        return [username, chat_id, message.get("recipient", {}).get("chat_type")]

    if command == "/accepted":
        accepted_list = str(db.get_many(cursor=bot_db_cursor, query=db_querys.chat_allowed_get))
        max_api.send_message(msg="Список чатов, куда отправляются оповещения об "
                                 "инцидентах: {0}".format(accepted_list))
    elif command == "/accept":
        if is_admin:
            result, reason = allow_chat(argument)
            if result:
                max_api.send_message(msg="Вы разрешили отправку оповещений об инцидентах в чат "
                                         "с id {0}".format(argument))
                max_api.send_message(msg="Администратор открыл доступ. Оповещения об инцидентах "
                                         "будут отправляться в этот чат.", ids=[int(argument)])
            else:
                max_api.send_message(msg=reason)
    elif command == "/deny":
        if is_admin:
            try:
                deny_chat_id = int(argument)
            except (TypeError, ValueError):
                max_api.send_message(msg="Не указан корректный id чата.")
                return None
            if deny_chat_id in allowed_chats_ids.get():
                allowed_chats_ids.remove(deny_chat_id)
                max_api.send_message("Инциденты НЕ будут отправляться в чат {0}".format(deny_chat_id))
            else:
                max_api.send_message("Чата с id {0} нет в списке оповещаемых.".format(deny_chat_id))
    elif command == "/banned":
        banned_list = str(db.get_many(cursor=bot_db_cursor, query=db_querys.chat_banned_get))
        max_api.send_message(msg="Список заблокированных чатов: {0}".format(banned_list))
    elif command == "/unban":
        if is_admin:
            try:
                unban_chat_id = int(argument)
            except (TypeError, ValueError):
                max_api.send_message(msg="Не указан корректный id чата.")
                return None
            log(f"Разбанить {unban_chat_id}")
            if unban_chat_id in banned_chats_ids.get():
                banned_chats_ids.remove(unban_chat_id)
                max_api.send_message("Разблокирован чат {0}".format(unban_chat_id))
            else:
                max_api.send_message("Чата с id {0} нет в списке заблокированных.".format(unban_chat_id))
    elif command == "/ban":
        if is_admin:
            try:
                ban_chat_id = int(argument)
            except (TypeError, ValueError):
                max_api.send_message(msg="Не указан корректный id чата.")
                return None
            # удалить из листа оповещаемых
            if ban_chat_id in allowed_chats_ids.get():
                allowed_chats_ids.remove(ban_chat_id)
            # добавить в лист заблокированных
            result, reason = ban_chat(ban_chat_id)
            if result:
                max_api.send_message(msg="Вы заблокировали чат с id {0}.".format(ban_chat_id))
            else:
                max_api.send_message(msg=reason)
    elif command == "/help":
        if is_admin:
            max_api.send_message(msg=help_message(), parse_mode="markdown")
    elif command == "/ping":
        if chat_id in allowed_chats_ids:
            if settings.ping_sticker_code:
                max_api.send_sticker(sticker_code=settings.ping_sticker_code, ids=[chat_id])
            else:
                max_api.send_message(msg="Бот на связи. {0}".format(datetime.now().strftime("%Y.%m.%d %H:%M:%S")),
                                     ids=[chat_id])
    elif command == "/debug":
        if is_admin:
            msg = f"last_incident_time = {last_incident_time.get()}\n" \
                  f"last_marker = {last_marker.get()}\n" \
                  f"chat_ids = {allowed_chats_ids.get()}\n" \
                  f"Последние логи: \n{logger}\n{max_api.logger}"
            max_api.send_message(msg=msg)
    return None


# Обработка нажатия inline-кнопки
def handle_callback(update):
    callback = update.get("callback", {})
    message = update.get("message", {})
    callback_id = callback.get("callback_id")
    callback_data = callback.get("payload") or ""
    callback_user = callback.get("user", {})
    callback_user_id = callback_user.get("user_id")
    callback_username = user_to_string(callback_user)
    # mid нужен, чтобы отредактировать сообщение с инцидентом
    callback_message_id = message.get("body", {}).get("mid")
    callback_chat_id = message.get("recipient", {}).get("chat_id")

    if callback_chat_id in banned_chats_ids or callback_user_id in banned_chats_ids:
        return
    log(f"Получен callback от пользователя {callback_username} ({callback_user_id}): {callback_data}")

    action, _, target = callback_data.partition(':')

    if callback_chat_id in allowed_chats_ids or callback_user_id in allowed_chats_ids:
        need_update = False
        if action == "apprv":
            # подтвердить инцидент
            log("Попытка подтвердить инцидент {inc} пользователем {user}".format(inc=target,
                                                                                user=callback_user_id))
            measures_text = "Инцидент подтвержден через бот MAX."
            message_text = "Инцидент подтвержден пользователем " \
                           "{username} ({userid}) через бот MAX.".format(username=callback_username,
                                                                        userid=callback_user_id)
            result = siem_set_incident_status(incident_id=target,
                                             status="Approved",
                                             measures=measures_text,
                                             message=message_text)
            if result == 204:
                log("Инцидент подтвержден")
                max_api.answer_callback(callback_id=callback_id, notification="Инцидент подтвержден")
            else:
                log("Ошибка при подтверждении инцидента, SIEM вернул код {0}".format(result))
                max_api.answer_callback(callback_id=callback_id, notification="Не удалось подтвердить инцидент")
            need_update = True
        elif action == "close":
            # закрыть инцидент
            log("Попытка закрыть инцидент {inc} пользователем {user}".format(inc=target,
                                                                            user=callback_user_id))
            measures_text = "Инцидент закрыт через бот MAX."
            message_text = "Инцидент закрыт пользователем " \
                           "{username} ({userid}).".format(username=callback_username,
                                                           userid=callback_user_id)
            result = siem_set_incident_status(incident_id=target,
                                             status="Closed",
                                             measures=measures_text,
                                             message=message_text)
            if result == 204:
                log("Инцидент закрыт")
                max_api.answer_callback(callback_id=callback_id, notification="Инцидент закрыт")
            else:
                log("Ошибка при закрытии инцидента: {0}".format(result))
                max_api.answer_callback(callback_id=callback_id, notification="Не удалось закрыть инцидент")
            need_update = True
        if action == "check" or need_update:
            # обновить инфо об инциденте
            incident = siem_get_incident_by_id(incident_id=target)
            if incident == 401:
                log("Не авторизован в SIEM, обновление информации об инциденте отложено")
                max_api.answer_callback(callback_id=callback_id,
                                        notification="Нет связи с SIEM, попробуйте позже")
                return
            incident_str = incident_to_string(incident)
            text = incident_str + "\n\nИнформация обновлена в " + str(datetime.now())
            keyboard = generate_incident_keyboard(incident=incident)
            max_api.edit_message(message_id=callback_message_id, msg=text, attachments=keyboard)
            log("В чате {0} обновлена информация об инциденте {1}".format(callback_chat_id, target))
            if action == "check":
                max_api.answer_callback(callback_id=callback_id, notification="Обновлена информация об инциденте")
            return

    if callback_chat_id == settings.max_admin_chat_id:
        if action == "accept":
            result, reason = allow_chat(allow_chat_id=target)
            if result:
                log(f"Администратор разрешил отправлять оповещения об инцидентах в чат {target}")
                text = f"Вы разрешили отправлять оповещения в чат {target} {datetime.now()}"
                max_api.edit_message(message_id=callback_message_id, msg=text, attachments=[])
                max_api.answer_callback(callback_id=callback_id, notification="Доступ разрешен")
                max_api.send_message(msg="Администратор открыл доступ. Оповещения об инцидентах "
                                         "будут отправляться в этот чат.", ids=[int(target)])
            else:
                max_api.answer_callback(callback_id=callback_id, notification="Не удалось разрешить доступ")
                max_api.send_message(msg="Произошла ошибка при добавлении чата в список: {0}".format(reason))
        elif action == "ignore":
            log(f"Администратор проигнорировал чат {target}")
            text = f"Вы проигнорировали чат с id {target} {datetime.now()}"
            max_api.edit_message(message_id=callback_message_id, msg=text, attachments=[])
            max_api.answer_callback(callback_id=callback_id, notification="Чат проигнорирован")
        elif action == "ban":
            result, reason = ban_chat(target)
            if result:
                text = f"Вы заблокировали чат с id {target} {datetime.now()}"
                max_api.edit_message(message_id=callback_message_id, msg=text, attachments=[])
                max_api.answer_callback(callback_id=callback_id, notification="Чат заблокирован")
                log(f"Администратор заблокировал чат с id {target}")
            else:
                max_api.answer_callback(callback_id=callback_id, notification="Не удалось заблокировать чат")
                max_api.send_message(msg=reason)


# Получить название чата (для оповещения администратора о новом групповом чате)
def chat_title(chat_id, default=None):
    chat = max_api.get_chat(chat_id)
    if isinstance(chat, dict) and chat.get("title"):
        return chat["title"]
    return default if default is not None else str(chat_id)


# Парсинг входящих событий из MAX
def check_new_chats():
    global last_marker
    log("Ожидаю события в MAX в течение {0} сек...".format(settings.max_updates_timeout))
    response = max_api.get_updates(last_marker.get())
    if response is None:
        log("Нет новых событий в MAX.")
        return 0
    updates = response.get("updates") or []
    if len(updates) == 0:
        # marker обновляем даже если событий не было, чтобы не переспрашивать одно и то же
        if response.get("marker"):
            last_marker.set(response["marker"])
        log("Нет новых событий в MAX.")
        return 0
    log("Обнаружены новые события, обработка...")
    new_chats = []
    for up in updates:
        try:
            update_type = up.get("update_type")
            if update_type == "message_created":
                new_chat = handle_message(up.get("message", {}))
                if new_chat:
                    new_chats.append(new_chat)
            elif update_type == "message_callback":
                handle_callback(up)
            elif update_type == "bot_started":
                # пользователь нажал "Начать" в диалоге с ботом
                started_chat_id = up.get("chat_id")
                if started_chat_id in banned_chats_ids:
                    continue
                started_user = up.get("user", {})
                log("Пользователь {0} начал диалог с ботом ({1})".format(user_to_string(started_user),
                                                                        started_chat_id))
                new_chats.append([user_to_string(started_user), started_chat_id, "dialog"])
            elif update_type == "bot_added":
                # бота добавили в групповой чат
                added_chat_id = up.get("chat_id")
                if added_chat_id in banned_chats_ids:
                    continue
                added_chat_title = chat_title(added_chat_id)
                log(f'Бот добавлен в чат {added_chat_title} ({added_chat_id})')
                new_chats.append([added_chat_title, added_chat_id, "chat"])
            elif update_type == "bot_removed":
                left_chat_id = up.get("chat_id")
                log(f'Бот удален из чата {left_chat_id}')
            elif update_type == "bot_stopped":
                stopped_chat_id = up.get("chat_id")
                log(f'Пользователь остановил бота в чате {stopped_chat_id}')
            else:
                log("Событие {0} не обрабатывается".format(update_type))
        except Exception as up_parse_ex:
            log("Непредвиденная ошибка при парсинге события из MAX: {0}".format(up_parse_ex))

    # marker указывает на следующее необработанное событие
    if response.get("marker"):
        last_marker.set(response["marker"])

    if len(new_chats):
        for new_chat in new_chats:
            new_chat_name = new_chat[0]
            new_chat_id = new_chat[1]
            # в MAX у групповых чатов id положительный, поэтому тип берем из события
            new_chat_type = "групповой чат" if new_chat[2] == "chat" else "чат с пользователем"
            new_chat_message = f"*Обнаружен новый {new_chat_type} {new_chat_name} (id {new_chat_id}).* \n" \
                               f"Разрешить отправку оповещений об инцидентах в этот чат?\n" \
                               f"✅ Разрешить - отправлять оповещения об инцидентах в этот чат.\n" \
                               f"⏹ Проигнорировать - не отправлять оповещения об инцидентах в этот чат.\n" \
                               f"⛔️ Заблокировать - больше не получать запросы на доступ этого чата."
            new_chat_keyboard = generate_chat_keyboard(chat_id=new_chat_id)
            max_api.send_message(msg=new_chat_message, attachments=new_chat_keyboard, parse_mode="markdown")
    log("... обработка закончена.")


# Основное тело скрипта
if __name__ == "__main__":
    # проверка токена бота
    bot_info = max_api.get_me()
    if bot_info is None:
        log("Не удалось получить информацию о боте MAX. Проверьте max_bot_token и доступность {0}".format(
            settings.max_api_url))
    else:
        log("Бот MAX: {0} (id {1})".format(bot_info.get("name") or bot_info.get("first_name"),
                                           bot_info.get("user_id")))
    # отправка сообщения администратору
    max_api.send_message(msg="Бот запущен.")
    work = True
    while work:
        try:
            # Запрос списка инцидентов
            incidents = siem_get_incidents()
            # Если не авторизован (случается при первом старте и при окончании действия токена)
            if incidents == 401:  # Unauthorised
                log("Не авторизован в SIEM, авторизуюсь.")
                # Авторизоваться повторно
                if not siem_get_bearer_token():
                    max_api.send_message(msg="Не удалось авторизоваться в SIEM: не правильный логин/пароль.")
                    raise Exception("Не правильный логин/пароль")
                continue
            # Если новые инциденты найдены
            if len(incidents) > 0:
                log("Найдены новые инциденты, пробую обработать их...")
                try:
                    max_api.send_message(msg="Новые инциденты:", ids=allowed_chats_ids.get())
                    for inc in reversed(incidents):
                        time.sleep(0.5)
                        keyboard = generate_incident_keyboard(incident=inc)
                        max_api.send_message(msg=incident_to_string(inc), ids=allowed_chats_ids.get(),
                                             attachments=keyboard)
                        # чтобы получить в следующий раз только новые инциденты, в переменную last_incident_time
                        # устанавливается время последнего найденного инцидента + 1 миллисекунда, чтобы исключить
                        # из проверки последний инцидент
                        new_last_inc_time = (datetime.fromisoformat(inc['created'][:23])
                                             + timedelta(milliseconds=1)).isoformat() + 'Z'
                        log("Try to set last_incident_time = {0}".format(new_last_inc_time))
                        last_incident_time.set(new_last_inc_time)
                except requests.exceptions.ConnectTimeout:
                    log("Не удалось отправить сообщение в MAX - ConnectTimeout")
                except ValueError as ex:
                    log("Ошибка при преобразовании даты/времени инцидента: {0}".format(ex))
                except Exception as ex:
                    log(ex)
                time.sleep(settings.pause_time)
            else:
                log("Не найдено новых инцидентов")
                time.sleep(settings.pause_time)
                check_new_chats()
        except Exception as ex:
            log(ex)
            max_api.send_message(msg="Произошла непредвиденная ошибка, бот остановлен.\n{0}".format(ex))
            raise
