set windows-shell := ['powershell.exe', '-Command']

name := "Oh-ShINT"
python := '3.10'

default:
    just --list


init: && lint-init
    @python -m pip install --upgrade pip
    @python -m pip install -r requirements.txt


[unix]
uninit:
    @rm -rf .venv

[unix]
[confirm]
clean-env: uninit
    #!/usr/bin/env bash
    set -euxo pipefail
    bin=$(which python{{ python }})
    virtualenv --python=$bin .venv

[windows]
[confirm]
clean-env:
    #!pwsh
    Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue ;
    python -m virtualenv --python="$env:USERPROFILE\AppData\Local\Programs\Python\Python{{ replace(python,'.','') }}\python.exe" .venv

alias cleanenv := clean-env
alias clean-venv := clean-env

[windows]
lint-init:
    #!pwsh
    param(
        [Parameter(Mandatory=$false, Position=0)][string[]]$needs = @('black', 'isort', 'autoflake')
    )

    # $installed is a list of installed package names
    $installed = (python -m pip list --format=json) | ConvertFrom-Json | Select-Object -ExpandProperty name


    foreach ($n in $needs) {
        if ($n -in $installed) {
            Write-Host "$n is already installed"
            $needs = $needs -ne $n
        }
    }

    if ($needs) {
        Write-Host "Installing $($needs -join ', ')"
        python -m pip install --upgrade $needs
    }


[unix]
lint-init:
    #!/usr/bin/env bash
    set -euxo pipefail
    if !(python -c "import isort" 2>/dev/null); then python -m pip install --upgrade isort ; fi
    if !(python -c "import black" 2>/dev/null); then python -m pip install --upgrade black ; fi
    if !(python -c "import autoflake" 2>/dev/null); then python -m pip install --upgrade autoflake ; fi

alias fmt-init := lint-init


lint: lint-init
    python -m isort .
    python -m black .
    python -m autoflake --in-place --remove-all-unused-imports --recursive .

alias fmt := lint


one *CMD:
    @python ./assistant.py one {{CMD}}