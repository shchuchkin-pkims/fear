# Определяем пути к curl
CURL_DIR = curl-8.15.0_5-win64-mingw
CURL_INCLUDE = $(CURL_DIR)/include
CURL_LIB = $(CURL_DIR)/lib

ifeq ($(OS),Windows_NT)
	CC = x86_64-w64-mingw32-gcc
	CFLAGS = -O2 -Wall -Wextra -pedantic -I"$(CURL_INCLUDE)"
	TARGET = updater.exe
	SRCDIR = .
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
	LDFLAGS = -L"$(CURL_LIB)" -l:libcurl.dll.a -lws2_32 -lbcrypt -lcrypt32 -static
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CC = gcc
		CFLAGS = -O2 -Wall -Wextra -pedantic
		TARGET = updater
		LDFLAGS = -lcurl
	endif
	ifeq ($(UNAME_S),Darwin)
		CC = gcc
		CFLAGS = -O2 -Wall -Wextra -pedantic
		TARGET = updater
		LDFLAGS = -lcurl
	endif
	SRCDIR = .
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
endif

.PHONY: all clean directories check-curl

all: check-curl directories $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

directories:
	@mkdir $(BUILDDIR)

clean:
ifeq ($(OS),Windows_NT)
	@if exist $(TARGET) del /q $(TARGET) 2>nul
	@if exist $(BUILDDIR) rmdir /s /q $(BUILDDIR) 2>nul
else
	@rm -f $(TARGET)
	@rm -rf $(BUILDDIR)
endif

# Проверка существования библиотек curl
check-curl:
ifeq ($(OS),Windows_NT)
	@echo "Checking curl library in $(CURL_LIB)..."
	@if not exist "$(CURL_LIB)" ( \
		echo "ERROR: Curl library directory not found: $(CURL_LIB)" && \
		echo "Current directory: $$(pwd)" && \
		echo "Directory contents:" && ls -la && \
		exit 1 \
	)
	@if not exist "$(CURL_LIB)/libcurl.a" ( \
		echo "ERROR: libcurl.a not found in $(CURL_LIB)" && \
		echo "Files in lib directory:" && ls -la "$(CURL_LIB)/" 2>/dev/null || echo "Cannot list lib directory" && \
		exit 1 \
	)
	@echo "Curl libraries found successfully"
else
	@echo "Checking curl development package..."
	@which curl-config >/dev/null 2>&1 || (echo "ERROR: curl development package not installed" && exit 1)
	@echo "Curl development package found"
endif

# Альтернативная версия с явным указанием файла библиотеки
static:
	$(CC) $(CFLAGS) -o $(TARGET) updater.c -L"$(CURL_LIB)" -l:libcurl.a -lws2_32 -lbcrypt -lcrypt32 -static

# Упрощенная версия для отладки
simple:
	$(CC) -O2 -o updater.exe updater.c -I"$(CURL_INCLUDE)" -L"$(CURL_LIB)" -lcurl -lws2_32 -lbcrypt -lcrypt32