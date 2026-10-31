# CTFOU Automatic Challenge Monitor & Read-only Solver

Checks **ctfou.saikolabs.in** every **10 minutes**; notices newly visible challenges, attempts bounded **offline/passive** extraction, optionally asks Groq AI to reason about the text, and sends **question name + category + points + flag candidate + explanation** to Telegram. **Never submits flags** or runs payloads against challenge servers.

## What you will receive

**New challenge alert**

```text
🆕 New CTFOU Challenge
Question: Four Digits Later
Category: Crypto
Points: 250
Challenge ID: 42
Link: https://ctfou.saikolabs.in/challenges
Solver: queued (no auto-submission)
```

**Answer alert**

```text
🚩 CTFOU Flag Found
Question: Four Digits Later
Category: Crypto
Points: 250
Challenge ID: 42
Flag: THMH{example_only}
Status: Extracted from challenge evidence; not submitted
Explanation: Decoded from Base64 in supplied attachment
Link: https://ctfou.saikolabs.in/challenges
```

The example flag is not a real answer. AI-derived results are explicitly marked `AI candidate — NOT verified`. Even extracted flags can be decoys and are not platform-verified.

## What it can solve

- Looks for THMH-format flags in visible challenge descriptions and attachments.
- Automatically examines text, ASCII strings, Base64, hex, ROT13, reverse strings, all Caesar shifts, gzip, bounded ZIP contents, image text metadata, and a few common RGB LSB layouts.
- Optional Groq LLM reasoning about the problem, with strict flag-format checking and no execution tools.
- Retries unsolved new challenges every 6 hours (configurable), not on every 10-minute poll.

**Limitations:** This is a working starter solver, not an autonomous general-purpose pwn/web/reversing agent. It doesn't perform active web attacks, exploit arbitrary hosts, reverse engineer executables, run arbitrary downloaded code, do OCR, solve advanced cryptanalysis, or guarantee correct answers. Complex challenges will often remain unsolved without human analysis or extra authorized solver modules.

## First setup: Telegram (about 5 steps)

1. In Telegram message `@BotFather` and choose `/newbot` to create a bot. Keep the bot token private.
2. Send a message such as `hello` to your new bot.
3. In your **own browser**, open `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`, replacing the placeholder. Find `message.chat.id`; this is `TELEGRAM_CHAT_ID`. Don't publish this URL or screenshots of the bot token. (If you get an empty `result`, send your bot a message and retry.)
4. On `https://ctfou.saikolabs.in/settings`, create a **personal CTFd access token**, preferably short-lived. Its name is `CTFOU_ACCESS_TOKEN`. The CTFd header used is `Authorization: Token ...`.
5. Optional: create your own Groq API key if you want AI-assisted answers (`GROQ_API_KEY`). This sends challenge names, descriptions and selected short **readable text** excerpts to Groq; keep private challenge content out of Groq if competition rules prohibit it. There is no embedded API key in this project.

**Do not send access tokens or bot tokens in ChatGPT messages.** Never commit real secrets to a repository. You must comply with the contest's rules on automation and external AI help.

## Option A: run in GitHub Actions every 10 minutes (computer may be off)

1. Create a new **private** GitHub repository (e.g. `ctfou-solver`) and upload **all** project files, including `.github/workflows/ctfou-monitor.yml` and `state/state.json`.
2. Go to repository **Settings → Secrets and variables → Actions → New repository secret** and add:
   - `CTFOU_ACCESS_TOKEN`
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `GROQ_API_KEY` (optional)
3. Repository **Settings → Actions → General → Workflow permissions**: allow **Read and write permissions** for GitHub Actions, because the workflow commits only `state/state.json` with challenge IDs and status.
4. Open **Actions → CTFOU 10-minute Challenge Monitor → Run workflow** to run the first check. By default this **baselines** existing challenges without alerting you about old questions.
5. On future runs, a challenge ID not present in state triggers the Telegram alert and is queued for solving. The cron expression runs at **:03, :13, :23, :33, :43, and :53 UTC** every hour. The schedule is in UTC; your Telegram notifications arrive at any local time.

**COST & TIMING:** GitHub Actions scheduling is **best-effort**, so runs can be delayed or skipped. Every-10-minute scheduling creates roughly **4,320 runs/month**; free runner minutes for a private repository may be exhausted, resulting in charges or paused workflows depending on account billing/limits. To stay free for continuous use, an existing Always Free Oracle VM with cron is preferable, or a Cloudflare Worker for detection plus on-demand solver runs. GitHub may disable scheduled workflows after repository inactivity.

To attempt existing challenges on the first run, change `SOLVE_EXISTING_ON_FIRST_RUN` from `'false'` to `'true'` **before the first run**, or delete/reset `state/state.json` to the initial state and rerun. That can cause many alerts and AI API calls.

## Option B: an Oracle Linux/Ubuntu VM (or other always-on Linux machine)

This uses Python's local state file and does **not** require GitHub or usage-based runner minutes. Python 3.11+ recommended.

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv   # Ubuntu
cd ~/ctfou-auto-solver
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Store **real credentials outside the repository** (e.g. in a permissions-restricted file `~/ctfou-secrets.env` with `chmod 600`) and source them when calling Python. Example launcher `~/ctfou-run.sh`:

```bash
#!/usr/bin/env bash
set -a
source "$HOME/ctfou-secrets.env"
set +a
cd "$HOME/ctfou-auto-solver"
exec .venv/bin/python -m ctfou
```

Then `chmod 700 ~/ctfou-run.sh` and `crontab -e`:

```cron
*/10 * * * * /home/YOUR_USERNAME/ctfou-run.sh >> /home/YOUR_USERNAME/ctfou-monitor.log 2>&1
```

Use an absolute username in cron; the `HOME` environment varies by machine. On Ubuntu, logs are `~/ctfou-monitor.log`. Oracle Linux uses `dnf` rather than `apt-get`.

## Option C: local Windows (PC must be on)

Install Python, run `py -m pip install -r requirements.txt`, and set your four environment variables using **user environment variables** (not in source code). In Windows Task Scheduler, create a task: **Trigger:** daily, repeat every 10 minutes indefinitely; **Action:** `py.exe`; **Arguments:** `-m ctfou`; **Start in:** full path to this project. Turn on 'Run whether user is logged on or not' if appropriate. Note that Windows may stop tasks on battery power depending on settings.

## Test without real credentials

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests use fake challenge objects, never connect to the live CTFOU website, and never submit flags. Do not mistake test flags for real answers.

## Controls and data handling

| Setting | Default | Effect |
|---|---|---|
| `FLAG_PREFIXES` | `THMH` | Case-insensitive allowed flag prefixes, comma separated |
| `SOLVE_EXISTING_ON_FIRST_RUN` | `false` | Ignore existing challenges at initialization |
| `MAX_SOLVES_PER_RUN` | `3` | Cap analysis work each poll |
| `RETRY_UNSOLVED_HOURS` | `6` | Backoff for unsolved puzzles |
| `NOTIFY_UNSOLVED` | `false` | Optional one-time 'couldn't solve yet' message |
| `GROQ_API_KEY` | empty | Enable optional AI reasoning |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Which Groq model to use |
| `CTFOU_STATE_PATH` | `state/state.json` | Local persistent state location |

`state/state.json` stores IDs, names, timestamps, solver status, and a digest of public challenge details only. It does **not** store flags, API access tokens, bot tokens, signed attachment tokens, or challenge descriptions. Every request to CTFd is GET; the project has **no** `/api/v1/challenges/attempt` requests. File downloads must use signed same-origin `/files/` paths; redirects and external file URLs are blocked. ZIP parsing is bounded to reduce zip-bomb risk. No downloaded executable, arbitrary script, or LLM-generated code is executed.

Failures: the API might require verification, block API tokens, rate-limit, or return non-standard data. The monitor then logs a generic error and tries the next scheduled run. A Telegram bot cannot DM you until you message the bot first.
