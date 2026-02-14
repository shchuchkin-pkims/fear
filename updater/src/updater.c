/**
 * @file updater.c
 * @brief Cross-platform automatic updater for F.E.A.R. Project
 *
 * Downloads and installs updates from GitHub Releases automatically.
 * Supports ZIP archives with automatic extraction and binary replacement.
 *
 * FEATURES:
 * - Fetches latest release from GitHub API
 * - Compares semantic versions (vX.Y.Z)
 * - Downloads matching asset (by prefix)
 * - Extracts ZIP archive
 * - Replaces current binary with updated version
 * - Cross-platform (Windows/Linux/macOS)
 *
 * CONFIGURATION:
 * Reads settings from updater.conf:
 * - repo_owner: GitHub repository owner
 * - repo_name: GitHub repository name
 * - app_path: Path to application binary to update
 * - version_arg: Command-line arg to get current version (e.g., "--version")
 * - asset_prefix: Prefix filter for release assets
 *
 * REQUIRES:
 * - libcurl (for HTTP requests)
 * - unzip utility (for archive extraction)
 *
 * @author F.E.A.R. Project contributors
 * @license MIT (free to use)
 * @version 1.0
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
  #include <direct.h>
  #define popen  _popen
  #define pclose _pclose
  #define PATH_SEP '\\'
#else
  #include <unistd.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #define PATH_SEP '/'
#endif

#include <curl/curl.h>

#define CONF_PATH_DEFAULT "updater.conf"
#define GITHUB_API_TPL "https://api.github.com/repos/%s/%s/releases/latest"
#define UA_STRING "updater-c/1.0 (+https://github.com/)"

#define MAX_URL 2048
#define MAX_PATH_LEN 1024
#define MAX_VER 128
#define MAX_PREFIX 128
#define MAX_OWNER 128
#define MAX_REPO 128
#define DL_BUF_CHUNK 8192

/**
 * @struct Config
 * @brief Updater configuration loaded from updater.conf
 *
 * Contains all settings needed to check for updates and download releases.
 */
typedef struct {
    char repo_owner[MAX_OWNER];      /**< GitHub repository owner */
    char repo_name[MAX_REPO];        /**< GitHub repository name */
    char app_path[MAX_PATH_LEN];     /**< Path to application binary to update */
    char version_arg[64];            /**< Command-line argument to get version (e.g., "--version") */
    char asset_prefix[MAX_PREFIX];   /**< Prefix filter for release assets (e.g., "fear-v") */
} Config;

/**
 * @struct MemBuf
 * @brief In-memory buffer for HTTP responses
 *
 * Used by libcurl to accumulate downloaded data in memory.
 */
typedef struct {
    char *data;    /**< Dynamically allocated buffer */
    size_t size;   /**< Current size of data in buffer */
} MemBuf;

/* ========== Utility Functions ========== */

/**
 * @brief Print error message and exit
 * @param msg Error message to display
 */
static void die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}

/**
 * @brief Print formatted error message and exit
 * @param fmt Format string
 * @param a Argument to format
 */
static void dief(const char *fmt, const char *a) {
    fprintf(stderr, "ERROR: ");
    fprintf(stderr, fmt, a);
    fprintf(stderr, "\n");
    exit(1);
}

/**
 * @brief Remove leading/trailing whitespace from string
 *
 * Modifies string in-place by removing:
 * - Trailing whitespace, newlines, carriage returns
 * - Leading whitespace
 *
 * @param s String to trim (modified in-place, can be NULL)
 */
static void trim(char *s) {
    if(!s) return;
    size_t n = strlen(s);
    /* Remove trailing whitespace */
    while(n>0 && (s[n-1]=='\r' || s[n-1]=='\n' || isspace((unsigned char)s[n-1]))) {
        s[--n] = '\0';
    }
    /* Remove leading whitespace */
    size_t i = 0;
    while(s[i] && isspace((unsigned char)s[i])) i++;
    if(i>0) memmove(s, s+i, strlen(s+i)+1);
}

static bool starts_with(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static void to_lower_inplace(char *s) {
    for(; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

/* Returns "windows-x86_64", "windows-x86", "linux-x86_64", "linux-arm64", ... */
static void detect_os_arch(char *out, size_t outsz) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *arch = "x86";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) arch = "x86_64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) arch = "arm64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) arch = "x86";
    snprintf(out, outsz, "windows-%s", arch);
#else
    const char *arch = "x86_64";
    #if defined(__aarch64__)
      arch = "arm64";
    #elif defined(__arm__)
      arch = "arm";
    #elif defined(__i386__)
      arch = "x86";
    #elif defined(__x86_64__)
      arch = "x86_64";
    #endif
    snprintf(out, outsz, "linux-%s", arch);
#endif
}

/* ---------- Configuration reading ---------- */

/**
 * @brief Load configuration from INI-style file
 *
 * Parses updater.conf file with key=value pairs.
 * Supports comments (#, ;) and blank lines.
 *
 * REQUIRED KEYS:
 * - repo_owner: GitHub repository owner
 * - repo_name: GitHub repository name
 * - app_path: Path to application binary
 * - asset_prefix: Asset name prefix filter
 *
 * OPTIONAL KEYS:
 * - version_arg: Command argument to get version (default: "--version")
 *
 * @param path Path to configuration file
 * @param cfg Output Config structure to populate
 *
 * @note Exits program if config file missing or incomplete
 */
static void load_config(const char *path, Config *cfg) {
    FILE *f = fopen(path, "r");
    if(!f) dief("Failed to open config: %s", path);
    char line[1024];
    memset(cfg, 0, sizeof(*cfg));
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if(line[0]=='#' || line[0]==';' || line[0]=='\0') continue;
        char *eq = strchr(line, '=');
        if(!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq+1;
        trim(key); trim(val);
        if(strcmp(key,"repo_owner")==0) strncpy(cfg->repo_owner,val,sizeof(cfg->repo_owner)-1);
        else if(strcmp(key,"repo_name")==0) strncpy(cfg->repo_name,val,sizeof(cfg->repo_name)-1);
        else if(strcmp(key,"app_path")==0)   strncpy(cfg->app_path,val,sizeof(cfg->app_path)-1);
        else if(strcmp(key,"version_arg")==0) strncpy(cfg->version_arg,val,sizeof(cfg->version_arg)-1);
        else if(strcmp(key,"asset_prefix")==0) strncpy(cfg->asset_prefix,val,sizeof(cfg->asset_prefix)-1);
    }
    fclose(f);
    if(cfg->repo_owner[0]=='\0' || cfg->repo_name[0]=='\0' ||
       cfg->app_path[0]=='\0'   || cfg->asset_prefix[0]=='\0') {
        die("Config is incomplete. Required: repo_owner, repo_name, app_path, asset_prefix. Optional: version_arg.");
    }
    if(cfg->version_arg[0]=='\0') strcpy(cfg->version_arg, "--version");

    // Fix app_path for platform - remove .exe on Linux, add .exe on Windows if missing
#ifdef _WIN32
    // On Windows, ensure .exe extension
    if(!strstr(cfg->app_path, ".exe")) {
        strncat(cfg->app_path, ".exe", sizeof(cfg->app_path) - strlen(cfg->app_path) - 1);
    }
#else
    // On Linux, remove .exe extension if present
    char *exe_ext = strstr(cfg->app_path, ".exe");
    if(exe_ext) {
        *exe_ext = '\0';  // Remove .exe extension
    }
#endif
}

/* ========== Version Detection ========== */

/**
 * @brief Extract semantic version from string
 *
 * Searches for version pattern like "vX.Y.Z" or "X.Y.Z" in string.
 * Supports 1-4 numeric components separated by dots.
 *
 * @param s Input string to search
 * @param out Output buffer for extracted version
 * @param outsz Size of output buffer
 * @return true if version found, false otherwise
 *
 * @example extract_semver("Version v1.2.3-beta", out, sz) -> "1.2.3"
 */
static bool extract_semver(const char *s, char *out, size_t outsz) {
    // Look for first subsequence like \d+(\.\d+){0,3}, allow 'v' prefix
    const char *p = s;
    while (*p) {
        if (*p=='v' && isdigit((unsigned char)p[1])) p++;
        if (isdigit((unsigned char)*p)) {
            size_t i=0;
            size_t dots=0;
            const char *q = p;
            char buf[128]={0};
            while (*q && (isdigit((unsigned char)*q) || *q=='.')) {
                if (*q=='.') dots++;
                if (i < sizeof(buf)-1) buf[i++] = *q;
                q++;
            }
            if (dots>=0 && i>0) { // minimal check
                strncpy(out, buf, outsz-1);
                out[outsz-1]='\0';
                return true;
            }
        }
        p++;
    }
    return false;
}

static void get_local_version(const Config *cfg, char *out_ver, size_t outsz) {
    out_ver[0] = '\0';
    char cmd[ MAX_PATH_LEN + 128 ];
    char app_path_to_check[MAX_PATH_LEN];
    const char *exec_path;  /* For Windows command execution */

    // First, check if the file exists in current directory
    // Extract filename, handling ./ or .\ prefix
    char check_path[MAX_PATH_LEN];
    const char *filename_only = cfg->app_path;

    if (cfg->app_path[0] == '.' && (cfg->app_path[1] == '/' || cfg->app_path[1] == '\\')) {
        filename_only = cfg->app_path + 2;  // Skip ./ or . with backslash
    }

    // For checking existence, we need the full relative path with ./
    // Build check_path: add ./ if not present
    if (cfg->app_path[0] == '.') {
        strncpy(check_path, cfg->app_path, sizeof(check_path) - 1);
    } else {
        snprintf(check_path, sizeof(check_path), ".%c%s", PATH_SEP, filename_only);
    }
    check_path[sizeof(check_path) - 1] = '\0';

    // Check if file exists in current directory
    #ifdef _WIN32
    bool file_exists_here = (_access(check_path, 0) == 0);
    #else
    bool file_exists_here = (access(check_path, F_OK) == 0);
    #endif

    if (file_exists_here) {
        // File is in current directory, use it directly
        strncpy(app_path_to_check, check_path, sizeof(app_path_to_check) - 1);
        app_path_to_check[sizeof(app_path_to_check) - 1] = '\0';
    } else {
        // File not in current directory, check if we're in bin/ subdirectory
        char cwd[MAX_PATH_LEN];
        #ifdef _WIN32
        _getcwd(cwd, sizeof(cwd));
        #else
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            strcpy(cwd, ".");
        }
        #endif

        size_t len = strlen(cwd);
        bool in_bin_dir = false;
        if (len >= 4) {
            const char *end = cwd + len - 4;
            #ifdef _WIN32
            if (strcmp(end, "\\bin") == 0 || strcmp(end, "/bin") == 0) {
                in_bin_dir = true;
            }
            #else
            if (strcmp(end, "/bin") == 0) {
                in_bin_dir = true;
            }
            #endif
        }

        if (in_bin_dir) {
            // We're in bin/ subdirectory, try parent directory
            #ifdef _WIN32
            snprintf(app_path_to_check, sizeof(app_path_to_check), "..\\%s", filename_only);
            #else
            snprintf(app_path_to_check, sizeof(app_path_to_check), "../%s", filename_only);
            #endif
        } else {
            // Use path as-is
            strncpy(app_path_to_check, cfg->app_path, sizeof(app_path_to_check) - 1);
            app_path_to_check[sizeof(app_path_to_check) - 1] = '\0';
        }
    }

    // Build command to execute
    #ifdef _WIN32
    /* On Windows, remove ./ or .\ prefix if present (CMD doesn't understand it) */
    exec_path = app_path_to_check;
    if (app_path_to_check[0] == '.' && (app_path_to_check[1] == '/' || app_path_to_check[1] == '\\')) {
        exec_path = app_path_to_check + 2;  /* Skip ./ or .\ */
    }
    snprintf(cmd, sizeof(cmd), "\"%s\" %s 2>&1", exec_path, cfg->version_arg);
    #else
    snprintf(cmd, sizeof(cmd), "'%s' %s 2>&1", app_path_to_check, cfg->version_arg);
    #endif

    printf("Running version check: %s\n", cmd);

    FILE *pp = popen(cmd, "r");
    if(!pp) {
        fprintf(stderr, "Warning: failed to run command for version check\n");
        return;
    }

    char buf[1024];
    size_t nread = fread(buf, 1, sizeof(buf)-1, pp);
    buf[nread] = '\0';
    pclose(pp);

    printf("Raw version output: %s\n", buf); // DEBUG output
    
    // Try to find "Program version: X.X.X" pattern
    const char *version_ptr = strstr(buf, "Program version:");
    if (version_ptr) {
        version_ptr += strlen("Program version:");
        while (*version_ptr && isspace((unsigned char)*version_ptr)) version_ptr++;
        
        // Extract version numbers
        char ver[128] = {0};
        int i = 0;
        while (*version_ptr && (isdigit((unsigned char)*version_ptr) || *version_ptr == '.') && i < sizeof(ver)-1) {
            ver[i++] = *version_ptr++;
        }
        ver[i] = '\0';
        
        if (strlen(ver) > 0) {
            strncpy(out_ver, ver, outsz-1);
            out_ver[outsz-1] = '\0';
            return;
        }
    }
    
    // Fallback: try to extract any semantic version pattern
    char semver[MAX_VER];
    if (extract_semver(buf, semver, sizeof(semver))) {
        strncpy(out_ver, semver, outsz-1);
        out_ver[outsz-1] = '\0';
    } else {
        strcpy(out_ver, "0.0.0"); // Default if nothing found
    }
}


/* ---------- Version comparison x.y.z ---------- */

static int vercmp(const char *a, const char *b) {
    // Compare by numbers, missing parts considered 0
    int pa[4]={0}, pb[4]={0};
    sscanf(a? a : "0", "%d.%d.%d.%d", &pa[0], &pa[1], &pa[2], &pa[3]);
    sscanf(b? b : "0", "%d.%d.%d.%d", &pb[0], &pb[1], &pb[2], &pb[3]);
    for(int i=0;i<4;i++){
        if(pa[i]<pb[i]) return -1;
        if(pa[i]>pb[i]) return 1;
    }
    return 0;
}

/* ---------- HTTP (libcurl) ---------- */

static size_t write_to_membuf(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    MemBuf *mb = (MemBuf*)userdata;
    char *newp = (char*)realloc(mb->data, mb->size + total + 1);
    if(!newp) return 0;
    mb->data = newp;
    memcpy(mb->data + mb->size, ptr, total);
    mb->size += total;
    mb->data[mb->size] = '\0';
    return total;
}

static void http_get_to_membuf(const char *url, MemBuf *mb) {
    CURL *curl = curl_easy_init();
    if(!curl) die("curl_easy_init failed");
    mb->data = NULL; mb->size = 0;

    // ПРАВИЛЬНАЯ SSL НАСТРОЙКА
    curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/vnd.github+json");
    hdrs = curl_slist_append(hdrs, "X-GitHub-Api-Version: 2022-11-28");
    hdrs = curl_slist_append(hdrs, "User-Agent: " UA_STRING);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_membuf);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, mb);
    
    CURLcode rc = curl_easy_perform(curl);
    if(rc != CURLE_OK) {
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
        dief("CURL error: %s", curl_easy_strerror(rc));
    }
    long code=0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if(code != 200) die("GitHub API returned non-200 OK");
}

static size_t write_to_file(void *ptr, size_t size, size_t nmemb, void *userdata) {
    FILE *f = (FILE*)userdata;
    return fwrite(ptr, size, nmemb, f);
}

static void http_download_to_file(const char *url, const char *filepath) {
    CURL *curl = curl_easy_init();
    if(!curl) die("curl_easy_init failed");
    FILE *f = fopen(filepath, "wb");
    if(!f) {
        curl_easy_cleanup(curl);
        dief("Failed to open file for writing: %s", filepath);
    }
    
    // ОТКЛЮЧАЕМ SSL ПРОВЕРКУ И ЗДЕСЬ
    curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "User-Agent: " UA_STRING);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    
    
    CURLcode rc = curl_easy_perform(curl);
    fclose(f);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if(rc != CURLE_OK) {
        remove(filepath);
        dief("Download error: %s", curl_easy_strerror(rc));
    }
}

/* ---------- Naive JSON parser ---------- */
/* We know GitHub releases/latest structure contains:
   "tag_name":"v1.2.3",
   "assets":[{"name":"...", "browser_download_url":"..."} ...]
*/

static bool json_find_string_value(const char *json, const char *key, char *out, size_t outsz) {
    // Look for "key":"value"
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if(!p) return false;
    p = strchr(p, ':');
    if(!p) return false;
    p++;
    // skip spaces
    while(*p && isspace((unsigned char)*p)) p++;
    if(*p!='"') return false;
    p++;
    size_t i=0;
    while (*p && *p!='"') {
        if(*p=='\\' && p[1]) { // simplified unescape
            p++;
        }
        if(i<outsz-1) out[i++] = *p;
        p++;
    }
    out[i]='\0';
    return true;
}

static bool json_find_asset_url_by_name(const char *json, const char *asset_name, char *out_url, size_t outsz) {
    // Look for block with "name":"asset_name" and nearby "browser_download_url":"..."
    const char *p = json;
    char keybuf[256];
    snprintf(keybuf, sizeof(keybuf), "\"name\":\"%s\"", asset_name);
    p = strstr(p, keybuf);
    if(!p) return false;
    // from this position look for next "browser_download_url"
    const char *q = strstr(p, "\"browser_download_url\"");
    if(!q) return false;
    // extract string value
    q = strchr(q, ':');
    if(!q) return false;
    q++;
    while(*q && isspace((unsigned char)*q)) q++;
    if(*q!='"') return false;
    q++;
    size_t i=0;
    while(*q && *q!='"') {
        if(*q=='\\' && q[1]) q++;
        if(i<outsz-1) out_url[i++]=*q;
        q++;
    }
    out_url[i]='\0';
    return true;
}

/* ---------- ZIP extraction ---------- */

/**
 * @brief Extract ZIP archive using system unzip utility
 * @param zip_path Path to ZIP file
 * @param dest_dir Destination directory for extraction
 * @return true on success, false on failure
 */
static bool extract_zip(const char *zip_path, const char *dest_dir) {
    char cmd[2048];
#ifdef _WIN32
    // For Windows, use PowerShell's Expand-Archive or external unzip
    snprintf(cmd, sizeof(cmd), "powershell -command \"Expand-Archive -Path '%s' -DestinationPath '%s' -Force\"",
             zip_path, dest_dir);
#else
    // For Linux/macOS, use unzip command
    snprintf(cmd, sizeof(cmd), "unzip -o '%s' -d '%s'", zip_path, dest_dir);
#endif

    printf("Extracting: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to extract ZIP (exit code: %d)\n", ret);
        return false;
    }
    return true;
}

/* ---------- File replacement ---------- */
// Files are now copied directly from the extracted archive to the current directory
// No need for individual binary replacement functions

/* ---------- Main logic ---------- */

int main(int argc, char **argv) {
    // Force immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("Starting updater...\n");
    printf("Current directory: ");
    system("cd");

    // Determine the correct target directory for update
    // If updater is in bin/ subdirectory, we need to update parent directory
    char target_dir[MAX_PATH_LEN] = ".";
    char cwd[MAX_PATH_LEN];

#ifdef _WIN32
    _getcwd(cwd, sizeof(cwd));
#else
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }
#endif

    printf("Working directory: %s\n", cwd);

    // Check if we're in a 'bin' subdirectory
    // Look for common pattern: ends with /bin or \bin
    size_t len = strlen(cwd);
    if (len >= 4) {
        const char *end = cwd + len - 4;
#ifdef _WIN32
        if (strcmp(end, "\\bin") == 0 || strcmp(end, "/bin") == 0) {
            strcpy(target_dir, "..");
            printf("Detected 'bin' directory - will update parent directory\n");
        }
#else
        if (strcmp(end, "/bin") == 0) {
            strcpy(target_dir, "..");
            printf("Detected 'bin' directory - will update parent directory\n");
        }
#endif
    }

    // Check if config exists
    FILE *test = fopen(CONF_PATH_DEFAULT, "r");
    if (!test) {
        printf("Error: File %s not found!\n", CONF_PATH_DEFAULT);
        getchar();
        return 1;
    }
    fclose(test);
    printf("Config found\n");

    (void)argc; (void)argv;
    Config cfg;
    load_config(CONF_PATH_DEFAULT, &cfg);

    printf("== Updater ==\n");
    printf("Repo: %s/%s\n", cfg.repo_owner, cfg.repo_name);
    printf("App : %s\n", cfg.app_path);

    char local_ver[MAX_VER]="";
    get_local_version(&cfg, local_ver, sizeof(local_ver));
    if(local_ver[0]=='\0') strcpy(local_ver, "0.0.0");
    printf("Installed version: %s\n", local_ver);

    char url[MAX_URL];
    snprintf(url, sizeof(url), GITHUB_API_TPL, cfg.repo_owner, cfg.repo_name);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    MemBuf mb = {0};
    printf("Checking latest release...\n");
    http_get_to_membuf(url, &mb);

    char tag_name[MAX_VER]="";
    if(!json_find_string_value(mb.data, "tag_name", tag_name, sizeof(tag_name))) {
        free(mb.data);
        die("tag_name not found in JSON");
    }
    // tag_name might be like "v1.2.3" - normalize for comparison
    char remote_ver[MAX_VER]="";
    if(tag_name[0]=='v' || tag_name[0]=='V') strncpy(remote_ver, tag_name+1, sizeof(remote_ver)-1);
    else strncpy(remote_ver, tag_name, sizeof(remote_ver)-1);
    remote_ver[sizeof(remote_ver)-1]='\0';
    printf("Latest version: %s\n", remote_ver);

    int cmp = vercmp(local_ver, remote_ver);
    if(cmp >= 0) {
        printf("You already have the latest version.\n");
        free(mb.data);
        curl_global_cleanup();
        return 0;
    }

    char osarch[64];
    detect_os_arch(osarch, sizeof(osarch));

    // Compose expected asset name - always use .zip for both platforms
    char asset_name[256];
    snprintf(asset_name, sizeof(asset_name), "%s-%s.zip", cfg.asset_prefix, osarch);
    printf("Looking for asset: %s\n", asset_name);

    char dl_url[MAX_URL]="";
    if(!json_find_asset_url_by_name(mb.data, asset_name, dl_url, sizeof(dl_url))) {
        free(mb.data);
        die("Suitable asset not found in release. Check asset_prefix/os-arch/filename in releases.");
    }
    free(mb.data);

    // Download ZIP archive
    char zip_path[MAX_PATH_LEN];
    snprintf(zip_path, sizeof(zip_path), "update_temp.zip");
    printf("Downloading to: %s\n", zip_path);
    http_download_to_file(dl_url, zip_path);

    // Extract ZIP to temporary directory
    char extract_dir[MAX_PATH_LEN];
    snprintf(extract_dir, sizeof(extract_dir), "update_temp");
    printf("Extracting archive...\n");

    // Create extraction directory
#ifdef _WIN32
    _mkdir(extract_dir);
#else
    mkdir(extract_dir, 0755);
#endif

    if (!extract_zip(zip_path, extract_dir)) {
        remove(zip_path);
        die("Failed to extract update archive");
    }

    // Remove downloaded ZIP
    remove(zip_path);

    printf("Copying updated files to: %s\n", target_dir);

#ifdef _WIN32
    // On Windows, we need to handle locked files (like fear_gui.exe)
    // Strategy: rename locked files to .old, then delete them on next startup
    printf("Preparing for file replacement...\n");

    // Try to rename fear_gui.exe if it exists in target directory
    char old_gui_path[MAX_PATH_LEN];
    char new_gui_path[MAX_PATH_LEN];
    snprintf(old_gui_path, sizeof(old_gui_path), "%s%cfear_gui.exe", target_dir, PATH_SEP);
    snprintf(new_gui_path, sizeof(new_gui_path), "%s%cfear_gui.exe.old", target_dir, PATH_SEP);

    // Check if fear_gui.exe exists
    if (_access(old_gui_path, 0) == 0) {
        // Try to delete old .old file if it exists
        if (_access(new_gui_path, 0) == 0) {
            printf("Removing previous backup: fear_gui.exe.old\n");
            remove(new_gui_path);
        }

        // Try to rename current fear_gui.exe to .old
        if (rename(old_gui_path, new_gui_path) == 0) {
            printf("Renamed locked fear_gui.exe to fear_gui.exe.old\n");
        } else {
            printf("Note: Could not rename fear_gui.exe (may not be running or already renamed)\n");
        }
    }
#endif

    // Copy all files from extracted directory to target directory
    // Important: We need to preserve directory structure (bin/, doc/, etc.)
#ifdef _WIN32
    // Windows: use robocopy if available, otherwise xcopy
    // robocopy is more reliable for directory copying
    char copy_cmd[2048];

    // Try robocopy first (available on Windows Vista+)
    // /E - copy subdirectories, including empty ones
    // /IS - include same files (overwrite even if same)
    // /IT - include tweaked files (overwrite even if timestamp is same)
    snprintf(copy_cmd, sizeof(copy_cmd),
             "robocopy \"%s\" \"%s\" /E /IS /IT",
             extract_dir, target_dir);

    printf("Running: robocopy \"%s\" \"%s\" /E /IS /IT\n", extract_dir, target_dir);
    fflush(stdout);
    int copy_ret = system(copy_cmd);
    printf("Robocopy exit code: %d\n", copy_ret);

    // Robocopy return codes: 0-7 are success, 8+ are errors
    // 0 = no files copied, 1 = files copied successfully, 2 = extra files/dirs
    // 3 = files copied with mismatches, etc.
    if (copy_ret >= 8) {
        // Robocopy failed or not available, try xcopy
        printf("Robocopy encountered errors, trying xcopy...\n");
        snprintf(copy_cmd, sizeof(copy_cmd),
                 "xcopy \"%s\" \"%s\" /E /H /Y /I /R /K /S",
                 extract_dir, target_dir);
        printf("Running: %s\n", copy_cmd);
        fflush(stdout);
        copy_ret = system(copy_cmd);
        printf("Xcopy exit code: %d\n", copy_ret);
        if (copy_ret != 0) {
            fprintf(stderr, "Warning: Copy command returned non-zero exit code %d\n", copy_ret);
        }
    } else {
        printf("Files copied successfully (robocopy code %d).\n", copy_ret);
    }
#else
    // Linux/macOS: use rsync or cp with proper options
    char copy_cmd[2048];

    // Use rsync if available (preserves structure), otherwise use cp with tar
    // First try rsync (most reliable for preserving structure)
    snprintf(copy_cmd, sizeof(copy_cmd),
             "which rsync >/dev/null 2>&1 && rsync -av '%s/' '%s/' 2>/dev/null || "
             "(cd '%s' && tar cf - .) | (cd '%s' && tar xf -)",
             extract_dir, target_dir, extract_dir, target_dir);

    printf("Running: %s\n", copy_cmd);
    int copy_ret = system(copy_cmd);

    if (copy_ret != 0) {
        fprintf(stderr, "Warning: Some files may not have been copied\n");
    }

    // Make all binaries in bin/ executable (relative to target_dir)
    snprintf(copy_cmd, sizeof(copy_cmd), "chmod +x '%s/bin/'* 2>/dev/null || true", target_dir);
    system(copy_cmd);
    snprintf(copy_cmd, sizeof(copy_cmd), "chmod +x '%s/'*.sh 2>/dev/null || true", target_dir);
    system(copy_cmd);
#endif

    printf("Files copied successfully.\n");

    // Cleanup extraction directory
    printf("Cleaning up temporary files...\n");
#ifdef _WIN32
    char cleanup_cmd[MAX_PATH_LEN + 32];
    snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rmdir /s /q \"%s\"", extract_dir);
    system(cleanup_cmd);
#else
    char cleanup_cmd[MAX_PATH_LEN + 32];
    snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf '%s'", extract_dir);
    system(cleanup_cmd);
#endif

    printf("Update completed. New version: %s\n", remote_ver);

#ifdef _WIN32
    // Check if we need to notify about GUI restart
    char check_old_gui[MAX_PATH_LEN];
    snprintf(check_old_gui, sizeof(check_old_gui), "%s%cfear_gui.exe.old", target_dir, PATH_SEP);
    if (_access(check_old_gui, 0) == 0) {
        printf("\n");
        printf("IMPORTANT: fear_gui.exe was running during update.\n");
        printf("Please restart the GUI application to complete the update.\n");
        printf("The old version will be removed automatically on next startup.\n");
    }
#endif

    curl_global_cleanup();
    return 0;
}