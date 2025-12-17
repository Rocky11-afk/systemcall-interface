// policy.c
// Implements policy handling logic for file access control
// Author: Ajay

#include "policy.h"
#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>

// Stores list of blocked file paths loaded from policy.json
char blocked[20][200];
int blocked_count = 0;

// Loads blocked file paths from a JSON policy file into memory
void load_policy(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) return;   // If policy file is not found, skip loading

    char buffer[2048];
    fread(buffer, 1, 2048, fp);
    fclose(fp);

    // Parse JSON content
    cJSON *json = cJSON_Parse(buffer);
    cJSON *arr = cJSON_GetObjectItem(json, "blocked_files");

    // Store blocked file paths in array
    blocked_count = cJSON_GetArraySize(arr);
    for (int i = 0; i < blocked_count; i++) {
        strcpy(blocked[i], cJSON_GetArrayItem(arr, i)->valuestring);
    }

    // Free JSON object from memory
    cJSON_Delete(json);
}

// Checks whether a given file path exists in the blocklist
int is_blocked(const char *path) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(path, blocked[i]) == 0)
            return 1;   // File access is blocked
    }
    return 0;           // File access is allowed
}
