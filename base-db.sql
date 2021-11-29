BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "functions" (
	"id"	INTEGER NOT NULL UNIQUE,
	"address"	INTEGER NOT NULL,
	"vector"	TEXT NOT NULL,
	"source"	TEXT NOT NULL,
	"name"	TEXT,
	"norm"	INTEGER,
	PRIMARY KEY("id"),
	UNIQUE("address","source")
);
COMMIT;
