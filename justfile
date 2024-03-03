set windows-shell := ['powershell.exe', '-Command']

name := "Oh-ShINT"

user_home := if os_family() == "windows" { env_var('UserProfile') } else { env_var('HOME') }
activate := if os_family() == "windows" { join(invocation_directory(), ".venv", "Scripts", "activate.bat") } else { "" }


[windows]
activate:
    @echo call {{activate}}


init: && lint-init
    @python -m pip install --upgrade pip
    @python -m pip install -r requirements.txt

[unix]
cleaninit:
    rm -rf .venv
    python -m virtualenv .venv

[windows]
cleaninit:
    Remove-Item -Recurse -Force .venv
    python -m virtualenv --python='C:\Python311\python.exe' .venv

[windows]
lint-init:
    #!pwsh
    param(
        [Parameter(Mandatory=$false, Position=0)][string[]]$needs = @('black', 'isort')
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

alias fmt-init := lint-init


lint: lint-init
    python -m isort .
    python -m black .

alias fmt := lint


one *CMD:
    @python ./assistant.py one {{CMD}}