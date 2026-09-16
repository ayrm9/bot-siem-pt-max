# # # # # # # # # # # # # # # # # # # #
# Типовые запросы к базе данных бота  #
# # # # # # # # # # # # # # # # # # # #

# Таблицы, которые должны быть в БД бота
tables_required = ("max_chats_allowed", "max_chats_denied", "variables",
                   "incident_messages", "incident_actions")

# Скрипт идемпотентный: выполняется при каждом старте и создает только недостающее.
# Так новые таблицы появляются и в уже существующих файлах БД, без ручной миграции.
tables_create = """
CREATE TABLE IF NOT EXISTS "max_chats_allowed" (
	"id"	INTEGER NOT NULL UNIQUE,
	"chat_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "max_chats_denied" (
	"id"	INTEGER NOT NULL UNIQUE,
	"chat_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "variables" (
	"id"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL UNIQUE,
	"value"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);
-- в какие чаты и каким сообщением ушел инцидент
CREATE TABLE IF NOT EXISTS "incident_messages" (
	"id"	INTEGER NOT NULL UNIQUE,
	"incident_id"	TEXT NOT NULL,
	"chat_id"	INTEGER NOT NULL,
	"message_id"	TEXT NOT NULL,
	"created"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE INDEX IF NOT EXISTS "idx_incident_messages" ON "incident_messages" ("incident_id");
-- кто и что сделал с инцидентом через бота
CREATE TABLE IF NOT EXISTS "incident_actions" (
	"id"	INTEGER NOT NULL UNIQUE,
	"incident_id"	TEXT NOT NULL,
	"text"	TEXT NOT NULL,
	"created"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE INDEX IF NOT EXISTS "idx_incident_actions" ON "incident_actions" ("incident_id");
INSERT INTO "variables" ("name") SELECT 'last_incident_time'
	WHERE NOT EXISTS (SELECT 1 FROM "variables" WHERE "name" = 'last_incident_time');
INSERT INTO "variables" ("name") SELECT 'last_marker'
	WHERE NOT EXISTS (SELECT 1 FROM "variables" WHERE "name" = 'last_marker');"""

tables_list = """SELECT name FROM sqlite_master WHERE type='table';"""

chat_allowed_insert = """INSERT INTO "main"."max_chats_allowed" ("chat_id") VALUES (?);"""

chat_allowed_get = """SELECT chat_id FROM max_chats_allowed;"""

chat_allowed_delete = """DELETE FROM max_chats_allowed WHERE chat_id=?;"""

chat_banned_insert = """INSERT INTO "main"."max_chats_denied" ("chat_id") VALUES (?);"""

chat_banned_get = """SELECT chat_id FROM max_chats_denied;"""

chat_banned_delete = """DELETE FROM max_chats_denied WHERE chat_id=?;"""

last_incident_time_get = """SELECT value FROM variables WHERE name='last_incident_time';"""

last_incident_time_set = """UPDATE variables set value = ? WHERE name = 'last_incident_time';"""

last_marker_get = """SELECT value FROM variables WHERE name='last_marker';"""

last_marker_set = """UPDATE variables set value = ? WHERE name = 'last_marker';"""

incident_message_insert = """INSERT INTO "main"."incident_messages"
	("incident_id", "chat_id", "message_id", "created") VALUES (?, ?, ?, ?);"""

incident_message_get = """SELECT chat_id, message_id FROM incident_messages
	WHERE incident_id = ? ORDER BY id;"""

incident_messages_cleanup = """DELETE FROM incident_messages WHERE created < ?;"""

incident_action_insert = """INSERT INTO "main"."incident_actions"
	("incident_id", "text", "created") VALUES (?, ?, ?);"""

incident_action_get = """SELECT text FROM incident_actions WHERE incident_id = ? ORDER BY id;"""

incident_actions_cleanup = """DELETE FROM incident_actions WHERE created < ?;"""
