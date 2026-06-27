# BSC Token Safety Checker

CLI tool that analyzes BSC tokens for rug pull indicators. Checks honeypot status, liquidity depth, holder concentration, and ownership renunciation in seconds.

## Features

- 🔍 **Honeypot detection** — Simulates buy + sell to see if you can exit
- 💧 **Liquidity check** — How deep is the PancakeSwap pair?
- 👑 **Ownership check** — Is the contract renounced?
- 🐋 **Holder concentration** — Does one wallet control everything?
- ✅ **BscScan verification** — Is source code verified? (with API key)
- 📊 **Safety score** — 0-100% rating

## Usage

```bash
# Single token
python bot/check.py 0x...

# Multiple tokens
python bot/check.py 0x... 0x... 0x...

# Interactive mode
python bot/check.py
```

## Example Output

```
============================================================
  BSC TOKEN SAFETY REPORT

  Token: MyToken (MTK)
  Address: 0x...
  LP Liquidity: 12.50 BNB ($7,125.00)

  ✅ Contract bytecode         PASS      Code size: 12,430 bytes
  ✅ Liquidity                 PASS      BNB liquidity: 12.50 BNB
  ✅ Honeypot                  PASS      Buy/sell works
  ⚠️  Ownership renounced      WARN      Not renounced
  ✅ Holder concentration      PASS      Owner holds 2.1%

  Score: 4.5/5 (90%)
  Verdict: ✅ SAFE
```

## Options

Set `BSCSCAN_API_KEY` environment variable for source verification:
```bash
export BSCSCAN_API_KEY=your_key_here
python bot/check.py 0x...
```

## Donation

If this tool helps you avoid a rug, consider a tip:

`0x6A3404e7fdeE519AaaB364E1C27Db07aa99Ec922`

## Requirements

- Python 3.10+
- `pip install web3 requests`
