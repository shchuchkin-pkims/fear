// updater.c
// Cross-platform GitHub Releases updater.
// Requires: libcurl
// Author: you. License: MIT (free to use).

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

#include <C:/Users/Evgeny/Documents/VS_Code/C/fear/updater/curl-8.15.0_5-win64-mingw/include/curl/curl.h>

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

typedef struct {
    char repo_owner[MAX_OWNER];
    char repo_name[MAX_REPO];
    char app_path[MAX_PATH_LEN];
    char version_arg[64];
    char asset_prefix[MAX_PREFIX];
} Config;

typedef struct {
    char *data;
    size_t size;
} MemBuf;

/* ---------- Utilities ---------- */

static void die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}

static void dief(const char *fmt, const char *a) {
    fprintf(stderr, "ERROR: ");
    fprintf(stderr, fmt, a);
    fprintf(stderr, "\n");
    exit(1);
}

static void trim(char *s) {
    if(!s) return;
    size_t n = strlen(s);
    while(n>0 && (s[n-1]=='\r' || s[n-1]=='\n' || isspace((unsigned char)s[n-1]))) { s[--n] = '\0'; }
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
}

/* ---------- Command execution to get local app version ---------- */

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
    
    #ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "\"%s\" %s 2>&1", cfg->app_path, cfg->version_arg);
    #else
    snprintf(cmd, sizeof(cmd), "'%s' %s 2>&1", cfg->app_path, cfg->version_arg);
    #endif
    
    FILE *pp = popen(cmd, "r");
    if(!pp) {
        fprintf(stderr, "Warning: failed to run %s for version\n", cfg->app_path);
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

/* ---------- File replacement ---------- */

static void build_temp_download_path(const char *app_path, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.download", app_path);
}

static void build_backup_path(const char *app_path, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.bak", app_path);
}

static void make_executable(const char *path) {
#ifndef _WIN32
    struct stat st;
    if (stat(path, &st)==0) {
        mode_t m = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
        chmod(path, m);
    }
#else
    (void)path;
#endif
}

static void replace_app_binary(const char *app_path, const char *new_path) {
    char bak[MAX_PATH_LEN];
    build_backup_path(app_path, bak, sizeof(bak));
#ifdef _WIN32
    // Delete old .bak if exists
    DeleteFileA(bak);
    // Rename current to .bak
    MoveFileExA(app_path, bak, MOVEFILE_REPLACE_EXISTING);
    // Move new to app location
    if(!MoveFileExA(new_path, app_path, MOVEFILE_REPLACE_EXISTING)) {
        // Try to revert
        MoveFileExA(bak, app_path, MOVEFILE_REPLACE_EXISTING);
        die("Failed to replace binary (MoveFileEx)");
    }
#else
    // Rename current to .bak (may fail if file doesn't exist)
    rename(app_path, bak);
    // Move new to app location
    if (rename(new_path, app_path)!=0) {
        // Revert
        rename(bak, app_path);
        die("Failed to replace binary (rename)");
    }
#endif
}

/* ---------- Main logic ---------- */

int main(int argc, char **argv) {
    // Force immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("Starting updater...\n");
    printf("Current directory: ");
    system("cd");
    
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

    // Compose expected asset name
    char asset_name[256];
#ifdef _WIN32
    snprintf(asset_name, sizeof(asset_name), "%s-%s.exe", cfg.asset_prefix, osarch);
#else
    snprintf(asset_name, sizeof(asset_name), "%s-%s", cfg.asset_prefix, osarch);
#endif
    printf("Looking for asset: %s\n", asset_name);

    char dl_url[MAX_URL]="";
    if(!json_find_asset_url_by_name(mb.data, asset_name, dl_url, sizeof(dl_url))) {
        free(mb.data);
        die("Suitable asset not found in release. Check asset_prefix/os-arch/filename in releases.");
    }
    free(mb.data);

    // Where to download
    char tmp_path[MAX_PATH_LEN];
    build_temp_download_path(cfg.app_path, tmp_path, sizeof(tmp_path));
    printf("Downloading to: %s\n", tmp_path);
    http_download_to_file(dl_url, tmp_path);

    // Make executable (for Linux/macOS)
    make_executable(tmp_path);

    // Replace main binary
    printf("Replacing %s -> %s\n", tmp_path, cfg.app_path);
    replace_app_binary(cfg.app_path, tmp_path);

    printf("Update completed. New version: %s\n", remote_ver);
    curl_global_cleanup();
    return 0;
}