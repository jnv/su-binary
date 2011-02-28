/*
** Copyright 2010, Adam Shanks (@ChainsDD)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <cutils/log.h>

#include <sqlite3.h>

#include "su.h"

// { int* pint; pint=(int*)data; ++(*pint); }

static int db_version_callback (void *version, int colCount, char **values,
        char **azColName)
{
    if (colCount == 1) {
        int* pint;
        pint = (int*)version;
        *pint = atoi(values[0]);
        return 0;
    } else {
        return -1;
    }
}

static int create_database(sqlite3 *db)
{
    char *zErrMsg;
    int rc;
    struct stat st;
    
    stat(REQUESTOR_DATA_PATH, &st);

    chown(REQUESTOR_DATABASES_PATH, st.st_uid, st.st_gid);
    chmod(REQUESTOR_DATABASE_PATH, 0660);
    chown(REQUESTOR_DATABASE_PATH, st.st_uid, st.st_gid);

    // Create the apps table
    rc = sqlite3_exec(db, APPS_TABLE_DEFINITION, NULL, NULL, &zErrMsg);
    if ( rc != SQLITE_OK ) {
        LOGE("Couldn't create apps table: %s", zErrMsg);
        return -1;
    }
    
    // Create the logs table
    rc = sqlite3_exec(db, LOGS_TABLE_DEFINITION, NULL, NULL, &zErrMsg);
    if ( rc != SQLITE_OK ) {
        LOGE("Couldn't create logs table: %s", zErrMsg);
        return -1;
    }
    
    // Create and populate the prefs table
    if ( sqlite3_exec(db, PREFS_TABLE_DEFINITION, NULL, NULL, &zErrMsg) != SQLITE_OK || 
            (sqlite3_exec(db,
            "INSERT OR REPLACE INTO prefs (key, value) VALUES (\"notifications\", \"1\");",
            NULL, NULL, &zErrMsg) != SQLITE_OK) ) {
        // Not mission critical, we won't kill it for this failing
        LOGE("Couldn't populate the prefs table: %s", zErrMsg);
    }
    
    // Set the database version
    if ( sqlite3_exec(db, "PRAGMA user_version = 6;", NULL, NULL, &zErrMsg) != SQLITE_OK ) {
        // Also not critical, log and move on
        LOGE("Failed to set the database version: %s", zErrMsg);
    }
    
    return 0;
}

static int upgrade_database(sqlite3 *db, int oldVersion, int newVersion)
{
    int upgradeVersion = oldVersion;
    char *zErrMsg;
    int rc;
    
    // Pattern for upgrade blocks
    //
    //    if (upgradeVersion == [the DATABASE_VERSION you set] - 1) {
    //        .. your upgrade logic ..
    //        upgradeVersion = [ the DATABASE_VERSION you set]
    //    }
    if (upgradeVersion < 5) {
        sqlite3_exec(db, "DROP TABLE IF EXISTS permissions;", NULL, NULL, &zErrMsg);
        create_database(db);
        return 0;
    }
    
    if (upgradeVersion == 5) {
        upgradeVersion = 6;
    }
    
    // Set the database version
    sqlite3_exec(db, "PRAGMA user_version = 6;", NULL, NULL, &zErrMsg);

    return 0;
}

sqlite3 *database_init()
{
    sqlite3 *db;
    int version, rc, databaseStatus = 0;
    char *zErrMsg = 0;

    mkdir(REQUESTOR_DATABASES_PATH, 0771);

    rc = sqlite3_open(REQUESTOR_DATABASE_PATH, &db);
    if ( rc ) {
        LOGE("Couldn't open database: %s", sqlite3_errmsg(db));
        return NULL;
    }

    sqlite3_exec(db, "PRAGMA user_version;", db_version_callback, &version, &zErrMsg);
    sqlite3_exec(db, "PRAGMA journal_mode = delete", NULL, NULL, NULL);

    if ( version <= 0 ) {
        databaseStatus = create_database(db);
    } else if ( version < DATABASE_VERSION ) {
        databaseStatus = upgrade_database(db, version, DATABASE_VERSION);
    }

    if ( databaseStatus < 0 ) {
        return NULL;
    }

    return db;
}

int database_check(sqlite3 *db, struct su_initiator *from, struct su_request *to)
{
    char sql[4096];
    char *zErrmsg;
    char **result;
    int nrow,ncol;
    int allow;
    struct timeval tv;

    sqlite3_snprintf(
        sizeof(sql), sql,
        "SELECT _id,name,allow FROM apps WHERE uid=%u AND exec_uid=%u AND exec_cmd='%q';",
        (unsigned)from->uid, to->uid, to->command
    );

    if (strlen(sql) >= sizeof(sql)-1)
        return DB_DENY;
        
    if (sqlite3_get_table(db, sql, &result, &nrow, &ncol, &zErrmsg) != SQLITE_OK) {
        LOGE("Database check failed with error message %s", zErrmsg);
        return DB_DENY;
    }
    
    if (nrow == 0 || ncol != 3)
        return DB_INTERACTIVE;
        
    if (strcmp(result[0], "_id") == 0 && strcmp(result[2], "allow") == 0) {
        LOGD("Add a log");
        if (strcmp(result[5], "1") == 0) {
            allow = DB_ALLOW;
        } else {
            allow = DB_DENY;
        }
        gettimeofday(&tv, NULL);
        sqlite3_snprintf(
            sizeof(sql), sql,
            "INSERT INTO logs (uid,name,date,type) VALUES (%u,\"%s\",(%ld*1000)+(%ld/1000),%s);",
            (unsigned)from->uid, result[4], tv.tv_sec, tv.tv_usec, result[5]
        );
        if (sqlite3_exec(db, sql, NULL, NULL, &zErrmsg) != SQLITE_OK) {
            LOGE("Inserting log failed with error %s", zErrmsg);
        }
        return allow;
    }

    sqlite3_free_table(result);
    
    return DB_INTERACTIVE;
}

int check_notifications(sqlite3 *db)
{
    char sql[4096];
    char *zErrmsg;
    char **result;
    int nrow,ncol;
    int notifications;
    
    sqlite3_snprintf(
        sizeof(sql), sql,
        "SELECT value FROM prefs WHERE key='notifications';"
    );
    
    if (sqlite3_get_table(db, sql, &result, &nrow, &ncol, &zErrmsg) != SQLITE_OK) {
        LOGE("Notifications check failed with error message %s", zErrmsg);
        return 0;
    }
    
    if (nrow == 0 || ncol != 1)
        return 0;
    
    if (strcmp(result[0], "value") == 0 && strcmp(result[1], "1") == 0)
        return 1;
        
    return 0;
}
