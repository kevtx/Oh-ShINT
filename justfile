set windows-shell := ['powershell.exe', '-Command']

name := "Oh-ShINT"
python_version := "3.10"
env_yml := "environment.yml"


default:
    just --list

conda-env:
    conda env create -f {{(quote(clean(env_yml)))}}

activate:
    conda activate {{name}}


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