ifeq ($(OS),Windows_NT)
	CC = x86_64-w64-mingw32-gcc
	CFLAGS = -O2 -Wall -Wextra -pedantic -I./include -D_WIN32_WINNT=0x0600
	LDFLAGS = -lsodium
	TARGET = fear.exe
	SRCDIR = src
	INCDIR = include
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
	LDFLAGS += -lws2_32 -static
	SODIUM_PATH = ./libsodium-win64
	CFLAGS += -I$(SODIUM_PATH)/include
	LDFLAGS += -L$(SODIUM_PATH)/lib
else
	CC = gcc
	CFLAGS = -O2 -Wall -Wextra -pedantic -I./include
	LDFLAGS = -lsodium
	TARGET = fear
	SRCDIR = src
	INCDIR = include
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
endif

.PHONY: all clean directories

all: directories $(TARGET)

$(TARGET): $(OBJECTS)
	@echo Linking $(TARGET)...
ifeq ($(OS),Windows_NT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) >> build.log 2>&1
else
	@echo "Linking $(TARGET)..." | tee -a build.log
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 2>&1 | tee -a build.log
	@echo "Build completed successfully" | tee -a build.log
endif

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@echo Compiling $<...
ifeq ($(OS),Windows_NT)
	$(CC) $(CFLAGS) -c $< -o $@ >> build.log 2>&1
else
	@echo "Compiling $<..." | tee -a build.log
	$(CC) $(CFLAGS) -c $< -o $@ 2>&1 | tee -a build.log
endif

directories:
	@mkdir $(BUILDDIR)

clean:
ifeq ($(OS),Windows_NT)
	@if exist $(TARGET) del /q $(TARGET) 2>nul
	@if exist build.log del /q build.log 2>nul
	@if exist $(BUILDDIR) rmdir /s /q $(BUILDDIR) 2>nul
else
	@rm -rf $(BUILDDIR) $(TARGET) build.log
endif

install-deps:
ifeq ($(OS),Windows_NT)
	@echo You need to install libsodium
else
	# Установка зависимостей (пример для Ubuntu/Debian)
	sudo apt-get update
	sudo apt-get install libsodium-dev
endif