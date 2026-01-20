# Autho Operator Node

Run an Autho Operator Node to participate in validation / signing of state transitions.

## Requirements

- Node.js **18+**
- Git

## Quick Install

### Windows (PowerShell)

```powershell
irm https://autho.pinkmahi.com/downloads/operator-node/quick-install.ps1 | iex
```

### macOS / Linux

```bash
curl -fsSL https://autho.pinkmahi.com/downloads/operator-node/quick-install.sh | bash
```

## What the installer does

- Creates an install directory:
  - Windows: `%USERPROFILE%\autho-operator-node`
  - macOS/Linux: `~/autho-operator-node`
- Clones the `Pink-Mahi/autho` repository
- Installs dependencies and builds the project
- Creates a start script

## Running

After installation:

### Windows

- Double click `start.bat`, or run:

```powershell
cd $env:USERPROFILE\autho-operator-node
.\start.ps1
```

### macOS/Linux

```bash
cd ~/autho-operator-node
./start.sh
```

## Configuration

Operator node is configured by environment variables. See the main project docs.

Common variables:

- `OPERATOR_ID`
- `OPERATOR_BTC_ADDRESS`
- `QUORUM_M`
- `QUORUM_N`
- `PEER_OPERATORS`

## Notes

- Operator nodes **sign**/validate state transitions. Keep your machine secure.
- If you only want to serve read-only data, run a **Gateway Node** instead.
