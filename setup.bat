@echo off

:: Ensure that Python 3 and pip are installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python 3 is not installed. Please install Python 3 first.
    exit /b
)

where pip >nul 2>nul
if %errorlevel% neq 0 (
    echo pip is not installed. Installing pip...
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python get-pip.py
    del get-pip.py
)

:: Create a virtual environment if not already present
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

:: Activate the virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

:: Install dependencies from requirements.txt
echo Installing dependencies...
pip install -r requirements.txt

:: Deactivate the virtual environment
deactivate

echo Setup complete. To activate the environment, run 'call venv\Scripts\activate'.
