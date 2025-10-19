# Quick Start Guide

## Build the Project

### One Command Build

**Linux/macOS:**
```bash
./build.sh
```

**Windows:**
```batch
build.bat
```

## What You Get

After build completes:

```
build/
├── fear_gui.exe      ← Main GUI application (with Qt files)
├── *.dll, platforms/ ← Qt dependencies
├── bin/              ← Console utilities
│   ├── fear.exe      ← Console client-server
│   ├── audio_call.exe← Audio calling tool
│   ├── key-exchange  ← Key exchange utility
│   └── updater.exe   ← Update manager
└── doc/
    └── manual.pdf    ← User manual
```

## Run the Application

**GUI Application:**
```bash
cd build
./fear_gui          # Linux/macOS
fear_gui.exe        # Windows
```

**Console Client:**
```bash
cd build/bin
./fear --help       # Linux/macOS
fear.exe --help     # Windows
```

**Audio Calls:**
```bash
cd build/bin
./audio_call        # Linux/macOS
audio_call.exe      # Windows
```

## Other Commands

**Clean temporary files:**
```bash
./build.sh clean     # Linux/macOS
build.bat clean      # Windows
```

**Rebuild everything:**
```bash
./build.sh rebuild   # Linux/macOS
build.bat rebuild    # Windows
```

## Need Help?

- Full build instructions: [BUILD.md](BUILD.md)
- Project documentation: [README.md](README.md)
- Issues: Check GitHub issues page
