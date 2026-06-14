#ifndef SECRETS_MANAGER_STORAGE_H
#define SECRETS_MANAGER_STORAGE_H

#include <sqlite3.h>

int storage_init(const char *db_path);
int storage_open(const char *db_path);
int storage_init_schema(const char *schema_path);
int storage_begin_transaction(void);
int storage_commit_transaction(void);
int storage_rollback_transaction(void);
sqlite3 *storage_get_db(void);
int storage_close(void);

#endif
