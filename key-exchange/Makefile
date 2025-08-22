ifeq ($(OS),Windows_NT)
	CC = x86_64-w64-mingw32-gcc
	CFLAGS = -O2 -Wall -Wextra -pedantic
	TARGET = key-exchange.exe
	SRCDIR = src
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
	LDFLAGS = -static
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CC = gcc
		CFLAGS = -O2 -Wall -Wextra -pedantic
		TARGET = key-exchange
		LDFLAGS = -lm
	endif
	ifeq ($(UNAME_S),Darwin)
		CC = gcc
		CFLAGS = -O2 -Wall -Wextra -pedantic
		TARGET = key-exchange
		LDFLAGS = -lm
	endif
	SRCDIR = src
	BUILDDIR = build
	SOURCES = $(wildcard $(SRCDIR)/*.c)
	OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
endif

.PHONY: all clean directories

all: directories $(TARGET)

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

# Упрощенная версия для простых случаев
simple:
	$(CC) $(CFLAGS) -o $(TARGET) key-exchange.c $(LDFLAGS)