from datetime import timedelta
import urllib.parse  # нужно для корректной отправки паролей со спецсимволами

# # # # # # #
# Настройки #
# # # # # # #

# Файл с БД бота
dbFileName = r"bot.db"

# Время в секундах между проверками инцидентов
pause_time = 3

# Часовой пояс для показа времени инцидентов пользователям (3 - Москва)
time_zone = timedelta(hours=3)

# Имя пользователя в SIEM
username = "siemlogin"

# Пароль пользователя в SIEM
password = urllib.parse.quote("SI3M-P@$$w0rd")

# ID клиента в SIEM
client_id = "mpx"

# secret пользователя в SIEM
client_secret = "cccccccc-dddd-3333-4444-eeeeeeeeeeee"

# URL для входа в SIEM. В конце строки не должно быть символа /
base_url = "https://siem.local"

# # # # # # # # # # #
# Настройки MAX     #
# # # # # # # # # # #

# Адрес Bot API мессенджера MAX. В конце строки не должно быть символа /
max_api_url = "https://botapi.max.ru"

# Токен бота MAX (выдается ботом @masterbot)
max_bot_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Время в секундах на ожидание новых событий в MAX (long polling, максимум 90)
max_updates_timeout = 30

# Максимальное число событий, получаемых из MAX за один запрос
max_updates_limit = 100

# ID чата с администратором в MAX
max_admin_chat_id = 123456789

# Список прокси для связи с MAX. Оставить пустым {}, чтобы не использовать прокси
max_proxys = {}

# Проверять сертификат сервера MAX
max_verify_ssl = True

# Максимальная длина текста сообщения в MAX
max_message_length = 4000

# Максимальное число отображаемых событий на инцидент
max_events_count = 5

# Header по умолчанию при обращениях к SIEM
default_header = {
    "User-Agent": "python-max-bot",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "*/*"
}

# Код стикера для ответа на команду /ping. Оставить пустым, чтобы отвечать текстом.
# В MAX стикер отправляется по своему коду (вложение типа sticker), ссылки на GIF не поддерживаются.
ping_sticker_code = ""
