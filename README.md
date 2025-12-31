# NovaShieldBot

Lightweight helpers for listing bot commands and safely using the anti-cheat API key.

## Usage

1. Set the anti-cheat key in the environment without hard-coding it:

   ```bash
   export ANTICHEAT_API_KEY="your-secret-token"
   ```

2. Show the available commands for help output:

   ```bash
   python -m src.bot
   ```

The `ANTICHEAT_API_KEY` is never logged or printed; it is only injected into the
`Authorization` header returned by `build_auth_headers`.

## Tests

Run the unit tests with pytest:

```bash
python -m pytest
```
