"""Минимальный клиент Bot API мессенджера MAX (https://dev.max.ru/docs-api).

Модуль повторяет набор операций, которые нужны боту оповещений:
получение обновлений (long polling), отправка и редактирование сообщений,
ответ на нажатие inline-кнопки и отправка стикера.
"""

import json
import time

import requests

import pretty_log
import settings

logger = pretty_log.PrettyLog(prefix="MAX", limit=10)
log = logger.logging

# Типы вложений и кнопок MAX
ATTACHMENT_INLINE_KEYBOARD = "inline_keyboard"
ATTACHMENT_STICKER = "sticker"
BUTTON_CALLBACK = "callback"

# Оформление кнопок: default / positive / negative
INTENT_DEFAULT = "default"
INTENT_POSITIVE = "positive"
INTENT_NEGATIVE = "negative"


def _url(api_path):
    return settings.max_api_url + api_path


def _params(extra=None):
    params = {}
    if extra:
        params.update({key: value for key, value in extra.items() if value is not None})
    return params


def _headers():
    # MAX ждет токен в заголовке Authorization БЕЗ префикса Bearer.
    # С префиксом сервер считает токеном всю строку и отвечает "Malformed access token".
    # Параметр access_token в query больше не поддерживается.
    return {"Authorization": settings.max_bot_token}


def _request(method, api_path, params=None, json_body=None, timeout=10):
    """Выполнить запрос к Bot API MAX. Возвращает (status_code, json) либо (None, None)."""
    try:
        response = requests.request(
            method=method,
            url=_url(api_path),
            params=_params(params),
            headers=_headers(),
            json=json_body,
            timeout=timeout,
            proxies=settings.max_proxys,
            verify=settings.max_verify_ssl,
        )
    except requests.exceptions.Timeout:
        log("Запрос {0} {1} не выполнен - Timeout".format(method, api_path))
        return None, None
    except requests.exceptions.ConnectionError:
        log("Запрос {0} {1} не выполнен - ConnectionError".format(method, api_path))
        return None, None
    except Exception as ex_request:
        log("Запрос {0} {1} не выполнен - {2}".format(method, api_path, ex_request))
        return None, None

    try:
        body = response.json()
    except ValueError:
        body = None

    if response.status_code != 200:
        log("MAX вернул код {0} на {1} {2}: {3}".format(response.status_code, method, api_path, body))

    return response.status_code, body


# Проверка токена и получение информации о боте
def get_me():
    status, body = _request("GET", "/me")
    if status == 200:
        return body
    return None


# Получение новых событий из MAX (long polling)
def get_updates(marker=None):
    """Вернуть словарь вида {"updates": [...], "marker": N} либо None."""
    params = {
        "limit": settings.max_updates_limit,
        "timeout": settings.max_updates_timeout,
    }
    # marker указывает на первое необработанное событие; при первом запуске не передается
    if marker:
        params["marker"] = marker
    status, body = _request(
        method="GET",
        api_path="/updates",
        params=params,
        # ждем ответ дольше, чем сервер держит соединение
        timeout=settings.max_updates_timeout + 10,
    )
    if status == 200 and isinstance(body, dict):
        return body
    return None


# Отправка сообщения в MAX
def send_message(msg, ids=None, attachments=None, parse_mode=None, max_retries=3, notify=True):
    """Отправить текст в перечисленные чаты.

    Если чаты не указаны, сообщение уходит администратору.
    Возвращает словарь {chat_id: message_id} по успешно отправленным сообщениям.
    """
    if ids is None:
        ids = [settings.max_admin_chat_id]
    sent = {}
    for index, chat_id in enumerate(ids):
        # Пауза между чатами, чтобы не упереться в антиспам MAX.
        # Стоит ДО отправки, а не после: иначе вызывающий код ждет ее, прежде чем
        # получить message_id, и не успевает записать факт отправки, если бота остановят.
        if index:
            time.sleep(0.4)
        body = {
            "text": msg[:settings.max_message_length],
            "notify": notify,
        }
        if attachments is not None:
            body["attachments"] = attachments
        if parse_mode is not None:
            body["format"] = parse_mode
        for attempt in range(max_retries):
            status, response = _request(
                method="POST",
                api_path="/messages",
                params={"chat_id": chat_id},
                json_body=body,
            )
            if status == 200:
                message_id = None
                if isinstance(response, dict):
                    message_id = response.get("message", {}).get("body", {}).get("mid")
                sent[chat_id] = message_id
                log("В чат {0} отправлено сообщение: {1}".format(chat_id, msg).replace("\n", " \\ "))
                break
            if status is None and attempt < max_retries - 1:
                # сетевая ошибка - пробуем еще раз
                time.sleep(1)
                continue
            log("Не удалось отправить сообщение в чат {0}. Код: {1}, ответ: {2}".format(
                chat_id, status, response))
            break
    return sent


# Редактирование сообщения в MAX
def edit_message(message_id, msg, attachments=None, parse_mode=None):
    """Изменить сообщение по его идентификатору (mid).

    Вложения при редактировании нужно передавать заново, иначе клавиатура пропадет.
    """
    body = {"text": msg[:settings.max_message_length]}
    if attachments is not None:
        body["attachments"] = attachments
    if parse_mode is not None:
        body["format"] = parse_mode
    status, response = _request(
        method="PUT",
        api_path="/messages",
        params={"message_id": message_id},
        json_body=body,
    )
    if status == 200:
        log("Изменено сообщение {0}".format(message_id))
        return True
    log("Не удалось изменить сообщение {0}. Код: {1}, ответ: {2}".format(message_id, status, response))
    return False


# Ответ на нажатие inline-кнопки
def answer_callback(callback_id, notification=None):
    """Закрыть callback. notification показывается пользователю всплывающим уведомлением."""
    body = {}
    if notification is not None:
        # MAX ограничивает длину уведомления
        body["notification"] = notification[:200]
    status, response = _request(
        method="POST",
        api_path="/answers",
        params={"callback_id": callback_id},
        json_body=body,
    )
    if status == 200:
        log("Отправлен ответ на callback: {0}".format(notification))
        return True
    log("Не удалось ответить на callback. Код: {0}, ответ: {1}".format(status, response))
    return False


# Отправка стикера в MAX
def send_sticker(sticker_code, ids=None):
    if ids is None:
        ids = [settings.max_admin_chat_id]
    attachments = [{"type": ATTACHMENT_STICKER, "payload": {"code": sticker_code}}]
    for chat_id in ids:
        status, response = _request(
            method="POST",
            api_path="/messages",
            params={"chat_id": chat_id},
            json_body={"attachments": attachments},
        )
        if status == 200:
            log("В чат {0} отправлен стикер {1}".format(chat_id, sticker_code))
        else:
            log("Не удалось отправить стикер в чат {0}. Код: {1}, ответ: {2}".format(
                chat_id, status, response))


# Информация о чате
def get_chat(chat_id):
    status, body = _request("GET", "/chats/{0}".format(chat_id))
    if status == 200:
        return body
    return None


# Сборка вложения с inline-клавиатурой
def inline_keyboard(buttons):
    """buttons - список строк клавиатуры, каждая строка - список кнопок."""
    return [{
        "type": ATTACHMENT_INLINE_KEYBOARD,
        "payload": {"buttons": buttons},
    }]


# Сборка callback-кнопки
def callback_button(text, payload, intent=INTENT_DEFAULT):
    # MAX ограничивает payload 256 символами
    return {
        "type": BUTTON_CALLBACK,
        "text": text,
        "payload": str(payload)[:256],
        "intent": intent,
    }


# Достать клавиатуру из уже отправленного сообщения (нужно при редактировании)
def keyboard_from_message(message):
    try:
        attachments = message.get("body", {}).get("attachments") or []
    except AttributeError:
        return None
    for attachment in attachments:
        if attachment.get("type") == ATTACHMENT_INLINE_KEYBOARD:
            return [attachment]
    return None


def dump(obj):
    """Компактная сериализация для логов."""
    try:
        return json.dumps(obj, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(obj)
