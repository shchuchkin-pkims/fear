# Сборка минимального FFmpeg для F.E.A.R. (Windows)

## Зачем

Предсобранные DLL с ffmpeg.org содержат **все** кодеки и фильтры (~238 MB).
Проект использует только 5 компонентов:

| Компонент | Зачем | Размер DLL |
|-----------|-------|------------|
| avcodec | VP8 + mjpeg декодеры | 102 MB |
| avfilter | **не используется** | 89 MB |
| avformat | demuxer для камеры (dshow) | 22 MB |
| avdevice | вход dshow (захват камеры) | 3.5 MB |
| swscale | масштабирование кадров | 2.1 MB |
| avutil | базовые утилиты | 2.9 MB |
| ffplay.exe | **не используется** | 17 MB |

Пересборка с `--disable-everything` даёт **~5-15 MB** статических `.a` вместо 238 MB DLL.
Финальный `.exe` получается ~20-30 MB вместо 100-400 MB, и **не требует DLL** при запуске.

---

## Требования

- **Windows 10/11**
- **MSYS2** — https://www.msys2.org/ (установить в `C:\msys64`)
- **Git** (для клонирования исходников FFmpeg)

---

## Пошаговая инструкция

### 1. Установить MSYS2

Скачать и установить с https://www.msys2.org/ в стандартную директорию `C:\msys64`.

После установки открыть **MSYS2 MINGW64** (не MSYS2 MSYS!) и обновить пакеты:

```bash
pacman -Syu
```

Если терминал закроется — открыть снова и повторить `pacman -Syu`.

### 2. Установить инструменты сборки

В терминале **MSYS2 MINGW64** выполнить:

```bash
pacman -S --noconfirm --needed \
    mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-make \
    mingw-w64-x86_64-yasm \
    mingw-w64-x86_64-nasm \
    mingw-w64-x86_64-pkg-config \
    mingw-w64-x86_64-libvpx \
    mingw-w64-x86_64-zlib \
    git
```

### 3. Подготовить исходники FFmpeg

Текущая папка `lib/ffmpeg-win64/` содержит предсобранные DLL.
Нужно **заменить её** на исходный код FFmpeg:

```bash
cd /c/path/to/fear-main/lib

# Удалить или переименовать старую папку с DLL
mv ffmpeg-win64 ffmpeg-win64-old

# Скачать исходники FFmpeg (последняя стабильная версия)
git clone --depth 1 --branch release/7.1 https://git.ffmpeg.org/ffmpeg.git ffmpeg-win64
```

> **Примечание:** ветка `release/7.1` — последняя стабильная на момент написания.
> Можно использовать `release/7.0` или `master`.

### 4. Собрать минимальный FFmpeg

#### Вариант A: Автоматически (рекомендуется)

Из командной строки Windows (cmd):

```cmd
cd C:\path\to\fear-main\lib
build-ffmpeg-static.bat
```

Скрипт автоматически найдёт MSYS2, запустит `build-ffmpeg-static.sh` и выполнит все шаги.

#### Вариант B: Вручную (в MSYS2 MINGW64)

```bash
cd /c/path/to/fear-main/lib
bash build-ffmpeg-static.sh
```

### Что делает скрипт

```
./configure \
    --enable-static --disable-shared    # статическая линковка, без DLL
    --disable-programs                   # без ffmpeg.exe/ffplay.exe/ffprobe.exe
    --disable-doc                        # без документации
    --disable-everything                 # отключить ВСЕ кодеки/форматы/фильтры
    --enable-avdevice                    # захват с устройств
    --enable-avformat                    # контейнеры/демуксеры
    --enable-avcodec                     # кодеки
    --enable-swscale                     # масштабирование видео
    --enable-avutil                      # базовые утилиты
    --enable-indev=dshow                 # DirectShow (камера на Windows)
    --enable-decoder=vp8                 # декодер VP8
    --enable-decoder=rawvideo            # декодер raw video
    --enable-decoder=mjpeg               # декодер MJPEG (некоторые камеры)
    --enable-decoder=bmp                 # декодер BMP
    --enable-encoder=libvpx_vp8          # VP8 энкодер через libvpx
    --enable-demuxer=rawvideo            # демуксер raw video
    --enable-demuxer=image2              # демуксер изображений
    --enable-muxer=rawvideo              # муксер raw video
    --enable-protocol=file               # протокол file://
    --enable-filter=scale                # фильтр масштабирования
    --enable-filter=format               # фильтр формата пикселей
    --enable-libvpx                      # внешняя библиотека libvpx
    --enable-gpl                         # лицензия GPL
    --extra-cflags="-O2"                 # оптимизация
    --extra-ldflags="-static"            # полностью статическая линковка
```

### 5. Проверить результат

После сборки в `lib/ffmpeg-win64/lib/` должны появиться статические библиотеки:

```
libavcodec.a      (~3-5 MB)
libavdevice.a     (~50 KB)
libavformat.a     (~500 KB)
libavutil.a       (~1 MB)
libswscale.a      (~200 KB)
```

Старые DLL (`avcodec-62.dll` и т.д.) будут удалены скриптом автоматически.

В `lib/libvpx/lib/` появится:

```
libvpx.a          (~3 MB)
```

### 6. Пересобрать проект

```cmd
cd C:\path\to\fear-main
build.bat rebuild
```

CMake автоматически обнаружит `.a` файлы вместо `.dll.a` и выполнит статическую линковку.
При этом не нужно копировать DLL рядом с `.exe` — всё внутри.

---

## Результат

| | До (shared DLL) | После (static) |
|---|---|---|
| FFmpeg в lib/ | 238 MB | ~5-10 MB |
| DLL при запуске | 6 штук (~213 MB) | 0 |
| Итого .exe | 100-400 MB | ~20-30 MB |

---

## Устранение проблем

### `configure: command not found`
Убедиться, что в `lib/ffmpeg-win64/` находятся **исходники** (файл `configure`), а не предсобранные бинарники.

### `nasm/yasm not found`
```bash
pacman -S mingw-w64-x86_64-nasm mingw-w64-x86_64-yasm
```

### `libvpx not found`
```bash
pacman -S mingw-w64-x86_64-libvpx
```

### Ошибки линковки `undefined reference` при сборке проекта
Статическая линковка FFmpeg требует системных библиотек Windows. CMakeLists.txt уже включает их (`bcrypt`, `strmiids`, `mfplat`, и т.д.). Если чего-то не хватает — добавить в `video_call/CMakeLists.txt` в секцию `FFMPEG_STATIC`.

### Хочу вернуть DLL-вариант
Скачать предсобранные библиотеки:
```
https://github.com/BtbN/FFmpeg-Builds/releases
```
Распаковать в `lib/ffmpeg-win64/`. CMake автоматически переключится на `.dll.a` файлы.
