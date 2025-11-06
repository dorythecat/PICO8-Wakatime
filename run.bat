@echo off
:: Buscar Python 3 en el sistema
set "PY_CMD="
python --version 2>NUL
if errorlevel 1 (
    py -3 --version 2>NUL
    if not errorlevel 1 (
        set "PY_CMD=py -3"
    )
) else (
    set "PY_CMD=python"
)

if not defined PY_CMD (
    echo Couldn't find Python 3 interpreter. Please install Python 3 and ensure it's in your PATH.
    pause
    exit /b 1
)

echo Usando: %PY_CMD%

:: Create a venv if it doesn't exist
if not exist venv\Scripts\python.exe (
    echo Creating virtual environment...
    %PY_CMD% -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo Error: could not create virtual environment.
        pause
        exit /b 1
    )
)

:: Activate the virtual environment
call venv\Scripts\activate.bat
if %ERRORLEVEL% neq 0 (
    echo Error: could not activate virtual environment.
    pause
    exit /b 1
)

echo Updating pip and installing dependencies...
python -m pip install --upgrade pip --disable-pip-version-check
python -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo Error: could not install dependencies.
    pause
    exit /b 1
)

:: Execute main.py with any passed arguments
echo Executing main.py...
python main.py %*
set "RC=%ERRORLEVEL%"

:: Log the return code and exit
echo Program exited with return code %RC%.

pause
exit /b %RC%
