# # # # # # # # # # # # # # # # # # # #
# Типовые запросы к базе данных бота  #
# # # # # # # # # # # # # # # # # # # #

# Таблицы, которые должны быть в БД бота
tables_required = ("max_chats_allowed", "max_chats_denied", "variables")

tables_create = """
CREATE TABLE "max_chats_allowed" (
	"id"	INTEGER NOT NULL UNIQUE,
	"chat_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE "max_chats_denied" (
	"id"	INTEGER NOT NULL UNIQUE,
	"chat_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE "variables" (
	"id"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL UNIQUE,
	"value"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);
INSERT INTO "main"."variables" ("name") VALUES ('last_incident_time');
INSERT INTO "main"."variables" ("name") VALUES ('last_marker');"""

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
