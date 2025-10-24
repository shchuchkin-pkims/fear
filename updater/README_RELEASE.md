# Updater - Release Instructions

## Как подготовить релиз для автообновления

### 1. Структура архива для GitHub Release

Updater ожидает ZIP-архив со следующей структурой:

```
fear-linux-x86_64.zip (или fear-windows-x86_64.zip)
├── bin/
│   ├── fear (или fear.exe)
│   ├── updater (или updater.exe)
│   ├── key-exchange (или key-exchange.exe)
│   ├── audio_call (или audio_call.exe)
│   ├── cacert.pem
│   └── updater.conf
├── fear_gui (или fear_gui.exe - опционально)
└── doc/
    └── manual.pdf (опционально)
```

**Важно:**
- Все файлы должны быть в корне архива или в подпапках (bin/, doc/, etc)
- Build-скрипты (build.sh, build.bat) НЕ включаются в релиз
- Скрипты `pack_release.sh` (Linux) и `pack_release.bat` (Windows) автоматически создают правильную структуру

### 2. Создание релиза на GitHub

1. Соберите проект:
   ```bash
   ./build.sh
   ```

2. Создайте ZIP-архив используя скрипт упаковки:

   **Для Linux (рекомендуется):**
   ```bash
   ./pack_release.sh 0.3.0
   ```

   **Для Windows (рекомендуется):**
   ```cmd
   pack_release.bat 0.3.0
   ```

   Скрипт автоматически:
   - Копирует все необходимые файлы
   - Включает только `doc/manual.pdf` (не весь doc/)
   - Создаёт правильную структуру директорий
   - Определяет платформу и архитектуру
   - Не включает build-скрипты в релиз

   **Вручную (если нужно):**

   Linux:
   ```bash
   cd build
   zip -r ../fear-linux-x86_64.zip bin/ fear_gui
   mkdir -p temp_doc && cp ../doc/manual.pdf temp_doc/
   zip -r ../fear-linux-x86_64.zip temp_doc/manual.pdf
   rm -rf temp_doc
   cd ..
   ```

   Windows:
   ```powershell
   cd build
   Compress-Archive -Path bin\*,fear_gui.exe -DestinationPath ..\fear-windows-x86_64.zip
   # Add manual.pdf
   mkdir temp_doc
   copy ..\doc\manual.pdf temp_doc\
   Compress-Archive -Path temp_doc\manual.pdf -DestinationPath ..\fear-windows-x86_64.zip -Update
   rmdir /S /Q temp_doc
   cd ..
   ```

3. Создайте новый релиз на GitHub:
   - Перейдите на страницу репозитория
   - Нажмите "Releases" → "Create a new release"
   - Создайте новый тег: `v0.3.0` (формат: `vX.Y.Z`)
   - Заполните описание релиза
   - Прикрепите ZIP-архивы:
     - `fear-linux-x86_64.zip`
     - `fear-windows-x86_64.zip`

### 3. Имена файлов

Updater автоматически определяет платформу и архитектуру:

| Платформа | Архив |
|-----------|-------|
| Linux x86_64 | `fear-linux-x86_64.zip` |
| Windows x86_64 | `fear-windows-x86_64.zip` |
| Linux ARM64 | `fear-linux-arm64.zip` |
| Windows ARM64 | `fear-windows-arm64.zip` |

**Формат:** `{asset_prefix}-{os}-{arch}.zip`

где `asset_prefix` берётся из `updater.conf` (по умолчанию: `fear`)

### 4. Тестирование

После публикации релиза проверьте обновление:

```bash
cd build/bin
./updater
```

Updater должен:
1. ✓ Определить текущую версию
2. ✓ Найти новый релиз на GitHub
3. ✓ Скачать правильный ZIP-архив для вашей платформы
4. ✓ Распаковать все файлы
5. ✓ Заменить все файлы проекта
6. ✓ Установить правильные права доступа (Linux)

**Важно:**
- Updater автоматически определяет свое расположение
- Если запущен из папки `bin/`, обновляет родительскую директорию
- Если запущен из корня проекта, обновляет текущую директорию
- При запуске из GUI файлы правильно копируются на уровень выше

### 5. Обновление версии в коде

Перед созданием релиза обновите версию в файле:
- `client-console/src/main.c` - константа `VERSION`

Пример:
```c
#define VERSION "0.3.0"
```

### 6. Конфигурация updater.conf

Файл `updater.conf` должен содержать:

```ini
repo_owner=shchuchkin-pkims
repo_name=fear
app_path=./fear
version_arg=--version
asset_prefix=fear
```

**Примечание:**
- `app_path` использует относительный путь `./fear` (или `./fear.exe`)
- Updater автоматически адаптирует расширение `.exe` под текущую ОС
- Updater должен запускаться из той же папки, где находится `fear`

### 7. Как работает обновление

1. **Проверка версии:** Updater запускает `./fear --version` из текущей директории и извлекает версию
2. **API запрос:** Получает последний релиз через GitHub API
3. **Сравнение:** Сравнивает семантические версии (X.Y.Z)
4. **Определение цели:** Автоматически определяет целевую директорию:
   - Если запущен из `bin/` → обновляет родительскую директорию
   - Если запущен из корня → обновляет текущую директорию
5. **Скачивание:** Загружает ZIP-архив для текущей платформы
6. **Распаковка:** Извлекает в временную папку `update_temp/`
7. **Копирование:** Копирует все файлы **с сохранением структуры директорий** (bin/, doc/, etc.)
8. **Установка прав:** Делает бинарники исполняемыми (Linux)
9. **Очистка:** Удаляет временные файлы

**Важно:** Используется `tar` для сохранения структуры директорий, что гарантирует правильное размещение файлов.

### 8. Требования

**Linux:**
- `unzip` утилита: `sudo apt-get install unzip`
- `libcurl` библиотека
- SSL сертификаты (`cacert.pem`)

**Windows:**
- PowerShell (встроен в Windows)
- `libcurl` DLL

### 9. Troubleshooting

**Ошибка: "Suitable asset not found"**
- Проверьте имя ZIP-файла в релизе
- Убедитесь, что формат: `fear-{os}-{arch}.zip`

**Ошибка: "Failed to extract ZIP"**
- Linux: установите `unzip`
- Windows: проверьте наличие PowerShell

**Ошибка: "Update binary not found"**
- Проверьте структуру архива
- Убедитесь, что файлы в папке `bin/`
