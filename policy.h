#ifndef POLICY_H
#define POLICY_H

// Load policy rules (allowlist & blocklist) from a config file
void load_policy(const char *file);

// Check whether a given file path is blocked or explicitly allowed
int is_blocked(const char *path);
int is_allowed(const char *path);

// Dynamically update policy rules at runtime
int add_to_blocklist(const char *path);
int add_to_allowlist(const char *path);

// Persist current policy rules back to file
int save_policy(const char *file);

// Load admin password and authenticate user before policy changes
void load_password(const char *file);
int authenticate();

#endif
