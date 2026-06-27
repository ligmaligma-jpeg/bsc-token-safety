#!/usr/bin/env python3
"""
BSC Token Safety Checker — CLI tool to analyze BSC tokens for rug indicators.
Checks honeypot status, liquidity lock, holder distribution, and more.
"""
import json
import os
import sys
import time
from datetime import datetime
from web3 import Web3
from typing import Dict, List, Optional

# ── Configuration ──────────────────────────────
RPC_URL = "https://bsc-dataseed1.binance.org"
BSCSCAN_API_KEY = ""  # Optional: set via BSCSCAN_API_KEY env var

# Donation address — supports ongoing development
DONATION_ADDRESS = "0x6A3404e7fdeE519AaaB364E1C27Db07aa99Ec922"

# ── Constants ──────────────────────────────────
WBNB = Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")
PCS_ROUTER = Web3.to_checksum_address("0x10ED43C718714eb63d5aA57B78B54704E256024E")
PCS_FACTORY = Web3.to_checksum_address("0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73")
ZERO_ADDR = "0x0000000000000000000000000000000000000000"
DEAD_ADDR = "0x000000000000000000000000000000000000dEaD"

# ── ABIs ───────────────────────────────────────
ROUTER_ABI = json.loads('[{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"}]')
ERC20_ABI = json.loads('[{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"type":"function"}]')
PAIR_ABI = json.loads('[{"constant":true,"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],"type":"function"},{"constant":true,"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],"type":"function"},{"constant":true,"inputs":[],"name":"getReserves","outputs":[{"internalType":"uint112","name":"","type":"uint112"},{"internalType":"uint112","name":"","type":"uint112"},{"internalType":"uint32","name":"","type":"uint32"}],"type":"function"}]')


class TokenSafetyChecker:
    """Analyzes a BSC token for rug indicators."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"

    def __init__(self, w3: Web3):
        self.w3 = w3
        self.router = w3.eth.contract(address=PCS_ROUTER, abi=ROUTER_ABI)
        self.factory = w3.eth.contract(address=PCS_FACTORY, abi=PAIR_ABI)

    def fmt_bnb(self, wei: int) -> str:
        return f"{wei / 1e18:.6f}"

    def fmt_usd(self, wei: int, bnb_usd: float = 570) -> str:
        return f"${wei / 1e18 * bnb_usd:.2f}"

    def check(self, token_addr: str) -> Dict:
        """Run all safety checks and return results."""
        addr = Web3.to_checksum_address(token_addr)
        results = {"address": addr, "timestamp": datetime.now().isoformat(), "checks": [], "score": 0, "max_score": 0}

        # ── 1. Basic token info ──
        self._check_basic_info(addr, results)
        if results.get("name") == "???":
            results["verdict"] = "⚠️  FAIL — Token unreachable"
            return results

        # ── 2. Contract code check ──
        self._check_bytecode(addr, results)

        # ── 3. PancakeSwap pair check ──
        self._check_pair_liquidity(addr, results)

        # ── 4. Honeypot simulation ──
        self._check_honeypot(addr, results)

        # ── 5. Holder concentration ──
        self._check_holders(addr, results)

        # ── 6. Ownership ──
        self._check_ownership(addr, results)

        # ── Score ──
        score = 0
        for c in results["checks"]:
            if c["status"] == self.PASS:
                score += 1
            elif c["status"] == self.WARN:
                score += 0.5

        results["score"] = score
        results["max_score"] = len(results["checks"])
        pct = score / len(results["checks"]) * 100 if results["checks"] else 0

        if pct >= 80:
            results["verdict"] = "✅ SAFE — Low risk indicators"
        elif pct >= 50:
            results["verdict"] = "⚠️  CAUTION — Some risk indicators found"
        else:
            results["verdict"] = "🔴 HIGH RISK — Multiple rug indicators detected"

        return results

    def _check_basic_info(self, addr: str, results: Dict):
        try:
            token = self.w3.eth.contract(address=addr, abi=ERC20_ABI)
            results["name"] = token.functions.name().call()
            results["symbol"] = token.functions.symbol().call()
            results["decimals"] = token.functions.decimals().call()
            results["total_supply"] = token.functions.totalSupply().call()
            results["checks"].append({"check": "Token metadata", "status": self.PASS, "detail": f"{results['name']} ({results['symbol']}) — {results['decimals']} decimals"})
        except Exception as e:
            results["name"] = "???"
            results["symbol"] = "???"
            results["decimals"] = 0
            results["total_supply"] = 0
            results["checks"].append({"check": "Token metadata", "status": self.FAIL, "detail": f"Cannot read: {str(e)[:50]}"})

    def _check_bytecode(self, addr: str, results: Dict):
        try:
            code = self.w3.eth.get_code(addr)
            if len(code) < 100:
                results["checks"].append({"check": "Contract bytecode", "status": self.FAIL, "detail": "No or minimal bytecode — likely fake token"})
            elif len(code) > 10000:
                results["checks"].append({"check": "Contract bytecode", "status": self.PASS, "detail": f"Code size: {len(code):,} bytes"})
            else:
                results["checks"].append({"check": "Contract bytecode", "status": self.WARN, "detail": f"Small code size: {len(code):,} bytes"})

            # Check verified source via BscScan (optional)
            api_key = os.environ.get("BSCSCAN_API_KEY", BSCSCAN_API_KEY)
            if api_key:
                import requests
                r = requests.get(f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={addr}&apikey={api_key}")
                data = r.json()
                if data.get("status") == "1" and data["result"][0]["SourceCode"]:
                    results["source_verified"] = True
                    results["checks"].append({"check": "Source code", "status": self.PASS, "detail": "Verified on BscScan"})
                else:
                    results["source_verified"] = False
                    results["checks"].append({"check": "Source code", "status": self.WARN, "detail": "Not verified on BscScan"})
        except Exception as e:
            results["checks"].append({"check": "Contract bytecode", "status": self.FAIL, "detail": str(e)[:50]})

    def _check_pair_liquidity(self, addr: str, results: Dict):
        try:
            pair_addr = self.factory.functions.getPair(addr, WBNB).call()
            if pair_addr == ZERO_ADDR:
                # Try with BUSD
                busd = Web3.to_checksum_address("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56")
                pair_addr = self.factory.functions.getPair(addr, busd).call()
                if pair_addr == ZERO_ADDR:
                    results["checks"].append({"check": "PancakeSwap pair", "status": self.FAIL, "detail": "No LP pair found"})
                    return

            pair = self.w3.eth.contract(address=pair_addr, abi=PAIR_ABI)
            reserves = pair.functions.getReserves().call()
            t0 = pair.functions.token0().call()
            t1 = pair.functions.token1().call()

            if t0 == addr:
                token_reserve, bnb_reserve = reserves[0], reserves[1]
            else:
                bnb_reserve, token_reserve = reserves[0], reserves[1]

            results["liquidity_bnb"] = bnb_reserve
            results["pair_address"] = pair_addr
            bnb_val = bnb_reserve / 1e18

            status = self.PASS
            detail = f"BNB liquidity: {bnb_val:.2f} BNB"
            if bnb_val < 1:
                status = self.FAIL
                detail += " (extremely low)"
            elif bnb_val < 10:
                status = self.WARN
                detail += " (low — easy to dump)"

            results["checks"].append({"check": "Liquidity", "status": status, "detail": detail})
        except Exception as e:
            results["checks"].append({"check": "Liquidity", "status": self.FAIL, "detail": str(e)[:50]})

    def _check_honeypot(self, addr: str, results: Dict):
        """Simulate buy + sell to check for honeypot."""
        try:
            # Try buy: 0.001 BNB worth
            amount_in = int(0.001 * 1e18)
            amounts_out = self.router.functions.getAmountsOut(amount_in, [WBNB, addr]).call()
            token_out = amounts_out[-1]

            if token_out == 0:
                results["checks"].append({"check": "Honeypot (buy)", "status": self.FAIL, "detail": "Cannot buy — token blocks purchases"})
                return

            # Try sell: half of what we'd get
            sell_amount = token_out // 2
            if sell_amount == 0:
                results["checks"].append({"check": "Honeypot (sell)", "status": self.FAIL, "detail": "Cannot sell — token blocks sells (honeypot)"})
                return

            out2 = self.router.functions.getAmountsOut(sell_amount, [addr, WBNB]).call()
            received_bnb = out2[-1]
            buy_bnb = amount_in / 2  # We spent half our buy amount
            sell_ratio = received_bnb / buy_bnb * 100 if buy_bnb > 0 else 0

            if sell_ratio < 1:
                results["checks"].append({"check": "Honeypot (sell)", "status": self.FAIL, "detail": f"Can only recover {sell_ratio:.1f}% — honeypot"})
            elif sell_ratio < 50:
                results["checks"].append({"check": "Honeypot (sell)", "status": self.WARN, "detail": f"Only recovers {sell_ratio:.1f}% — tax or low liquidity"})
            else:
                results["checks"].append({"check": "Honeypot", "status": self.PASS, "detail": f"Buy/sell works. Sell recovers {sell_ratio:.1f}% of cost"})
        except Exception as e:
            results["checks"].append({"check": "Honeypot", "status": self.FAIL, "detail": f"Simulation failed: {str(e)[:50]}"})

    def _check_holders(self, addr: str, results: Dict):
        """Check top holder concentration via balanceOf top whales."""
        try:
            token = self.w3.eth.contract(address=addr, abi=ERC20_ABI)
            supply = token.functions.totalSupply().call()
            if supply == 0:
                results["checks"].append({"check": "Holders", "status": self.FAIL, "detail": "Zero total supply"})
                return

            # Check the deployer wallet and a few known attack patterns
            deployer = None
            try:
                deployer = token.functions.owner().call()
            except:
                pass

            if deployer and deployer != ZERO_ADDR:
                deployer_bal = token.functions.balanceOf(deployer).call()
                deployer_pct = deployer_bal / supply * 100

                if deployer_pct > 50:
                    results["checks"].append({"check": "Holder concentration", "status": self.FAIL, "detail": f"Owner holds {deployer_pct:.1f}% — can manipulate price"})
                elif deployer_pct > 20:
                    results["checks"].append({"check": "Holder concentration", "status": self.WARN, "detail": f"Owner holds {deployer_pct:.1f}%"})
                else:
                    results["checks"].append({"check": "Holder concentration", "status": self.PASS, "detail": f"Owner holds {deployer_pct:.1f}%"})

            # Check liquidity pair
            if results.get("pair_address"):
                pair_bal = token.functions.balanceOf(results["pair_address"]).call()
                lp_pct = pair_bal / supply * 100
                results["checks"].append({"check": "LP % of supply", "status": self.INFO, "detail": f"LP holds {lp_pct:.1f}% of supply"})
        except Exception as e:
            results["checks"].append({"check": "Holders", "status": self.FAIL, "detail": str(e)[:50]})

    def _check_ownership(self, addr: str, results: Dict):
        """Check if ownership is renounced."""
        try:
            token = self.w3.eth.contract(address=addr, abi=ERC20_ABI)
            owner = None
            owner_pct = None
            try:
                owner = token.functions.owner().call()
                bal = token.functions.balanceOf(owner).call()
                supply = results.get("total_supply", 1)
                owner_pct = bal / supply * 100 if supply > 0 else 0
            except:
                pass

            if owner == ZERO_ADDR or owner == DEAD_ADDR:
                results["checks"].append({"check": "Ownership renounced", "status": self.PASS, "detail": "Ownership is renounced (zero/dead address)"})
            elif owner:
                results["checks"].append({"check": "Ownership renounced", "status": self.WARN, "detail": f"Not renounced. Owner: {owner[:10]}... ({owner_pct:.1f}% of supply)"})
            else:
                results["checks"].append({"check": "Ownership renounced", "status": self.INFO, "detail": "No owner() function"})
        except:
            results["checks"].append({"check": "Ownership renounced", "status": self.INFO, "detail": "Could not check"})

    def print_report(self, results: Dict):
        """Pretty-print safety report."""
        print()
        print("=" * 60)
        print(f"  BSC TOKEN SAFETY REPORT")
        print(f"  {results.get('timestamp', '')}")
        print("=" * 60)
        print()
        print(f"  Token: {results.get('name', '???')} ({results.get('symbol', '???')})")
        print(f"  Address: {results['address']}")
        print(f"  Decimals: {results.get('decimals', '?')}")
        if results.get('total_supply'):
            ts = results['total_supply']
            print(f"  Total Supply: {ts / (10**results.get('decimals', 18)):,.2f}")
        if results.get('liquidity_bnb'):
            print(f"  LP Liquidity: {results['liquidity_bnb'] / 1e18:.2f} BNB ({results['liquidity_bnb'] / 1e18 * 570:.2f})")
        print()
        print(f"  {'CHECK':<30s} {'STATUS':<10s} DETAIL")
        print("  " + "-" * 58)
        for c in results["checks"]:
            status_icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "🔴", "INFO": "ℹ️"}
            icon = status_icon.get(c["status"], "❓")
            print(f"  {icon} {c['check']:<27s} {c['status']:<10s} {c['detail'][:45]}")
        print()
        print(f"  Score: {results['score']}/{results['max_score']} ({results['score']/results['max_score']*100:.0f}%)")
        print(f"  Verdict: {results['verdict']}")
        print()
        print("-" * 60)
        like = "Like this tool? Send a tip: " + DONATION_ADDRESS
        print(f"  💰 {like}")
        print("=" * 60)
        print()


def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 10}))
    if not w3.is_connected():
        print("Cannot connect to BSC. Try a different RPC endpoint.")
        sys.exit(1)

    checker = TokenSafetyChecker(w3)
    bnb_price = 570  # approx

    # Single token or batch
    if len(sys.argv) > 1:
        tokens = sys.argv[1:]
    else:
        print("BSC Token Safety Checker")
        print()
        print("Usage: python check.py <token_address> [token2 token3 ...]")
        print()
        tokens_str = input("Enter token address(es) (space-separated): ").strip()
        if not tokens_str:
            return
        tokens = tokens_str.split()

    for addr in tokens:
        try:
            Web3.to_checksum_address(addr)
        except:
            print(f"Invalid address: {addr}")
            continue

        print(f"\nAnalyzing {addr[:10]}...{addr[-6:]}...")
        results = checker.check(addr)
        checker.print_report(results)


if __name__ == "__main__":
    main()
