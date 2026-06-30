@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   PHANTOM COMPLIANCE -- EXE Build Script
echo   Builds PhantomCompliance.exe (WITHOUT model file)
echo ============================================================
echo.

:: ── Check Python ────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ and add to PATH.
    pause & exit /b 1
)

:: ── Check / install PyInstaller ─────────────────────────────────
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

:: ── Record fresh integrity baseline before baking ───────────────
echo [INFO] Recording integrity baseline...
python -c "import core.tamper_detection; core.tamper_detection.record_new_baseline()" 2>nul

:: ── Clean previous build ────────────────────────────────────────
if exist "dist\PhantomCompliance" (
    echo [INFO] Removing old dist\PhantomCompliance...
    rmdir /s /q "dist\PhantomCompliance"
)
if exist "build\PhantomCompliance" (
    echo [INFO] Removing old build\PhantomCompliance...
    rmdir /s /q "build\PhantomCompliance"
)

:: ── Run PyInstaller ─────────────────────────────────────────────
echo [INFO] Running PyInstaller...
pyinstaller PhantomCompliance.spec --noconfirm --clean

if errorlevel 1 (
    echo.
    echo [FAILED] PyInstaller build failed. Check errors above.
    pause & exit /b 1
)

:: ── Create user-facing models\ placeholder ──────────────────────
set DIST=dist\PhantomCompliance
echo [INFO] Creating models\ folder for the GGUF model...
if not exist "%DIST%\models" mkdir "%DIST%\models"

:: Write a README so the user knows exactly what to do
(
echo PhantomCompliance — AI Model Folder
echo =====================================
echo.
echo Place your GGUF model file in THIS folder:
echo.
echo   models\Llama-3.2-3B-Instruct-Q4_K_M.gguf
echo.
echo You can download the model from:
echo   https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF
echo   (file: Llama-3.2-3B-Instruct-Q4_K_M.gguf  ~1.9 GB^)
echo.
echo Without the model, Phantom Compliance runs in offline/degraded mode.
echo The system still works fully for rule-based compliance tasks.
echo.
echo To use a CUSTOM model (any GGUF^):
echo   1. Place the .gguf file here.
echo   2. Open config.json in %%APPDATA%%\PhantomCompliance\
echo   3. Set:  "model_path": "C:\\path\\to\\your_model.gguf"
echo   4. Restart PhantomCompliance.exe.
echo.
echo llama-server.exe is included in the resources\ folder.
echo It is started automatically when a model is detected.
) > "%DIST%\models\README.txt"

:: ── Copy llama-server + DLLs to resources\ ──────────────────────
echo [INFO] Verifying resources\llama-server.exe is present...
if not exist "%DIST%\resources\llama-server.exe" (
    echo [WARN] llama-server.exe not found in dist\resources — copying from source...
    if not exist "%DIST%\resources" mkdir "%DIST%\resources"
    xcopy /E /Y /Q "resources\*" "%DIST%\resources\"
)

:: ── Write a launch README at dist root ──────────────────────────
(
echo ============================================================
echo   PHANTOM COMPLIANCE  —  Quick-Start Guide
echo ============================================================
echo.
echo 1. [OPTIONAL] Place your model in:
echo      models\Llama-3.2-3B-Instruct-Q4_K_M.gguf
echo    ^(see models\README.txt for full instructions^)
echo.
echo 2. Double-click  PhantomCompliance.exe
echo    - Without a model: works in offline / rule-based mode.
echo    - With a model   : full AI-powered compliance mode.
echo.
echo 3. Open browser at  http://127.0.0.1:5000
echo    Default login:  admin  /  (see console output on first run^)
echo.
echo 4. To run without the LLM:
echo      PhantomCompliance.exe --no-llm
echo.
echo ============================================================
) > "%DIST%\README.txt"

echo.
echo ============================================================
echo   BUILD COMPLETE!
echo   Output: %CD%\%DIST%\
echo.
echo   NEXT STEPS:
echo     1. Copy your GGUF model to:
echo        %CD%\%DIST%\models\Llama-3.2-3B-Instruct-Q4_K_M.gguf
echo     2. Run: %DIST%\PhantomCompliance.exe
echo.
echo   The exe works WITHOUT the model in offline mode.
echo ============================================================
echo.

pause
