#!/usr/bin/env python3
"""PYNQ-Z1 transport for the unified Ascon core (`ascon_aead_hash_axi`).

Loads the overlay built by scripts/build_pynq_overlay.tcl (build/ascon_pynq.bit
+ .hwh), finds the core's AXI4-Lite window and hands it to the register-level
driver in ascon_axi.py.  Run on the board as root (PYNQ default).

    from ascon_pynq_driver import open_hw
    core = open_hw()                       # AxiEngine over pynq.MMIO
    core = open_hw(use_c=True)             # MmioCEngine (C block loop, faster)
    digest = core.hash256(b"abc")

The previous file of this name drove the old DMA-based Kria design and is
obsolete: the unified core is a mailbox-style AXI4-Lite slave (see
docs/REGISTER_MAP.md).
"""
from __future__ import annotations

import os
import sys
import time
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ascon_axi import DEFAULT_BASE_ADDR, AsconAxiLite  # noqa: E402
from ascon_engines import AxiEngine  # noqa: E402

DEFAULT_BITSTREAM = os.path.normpath(os.path.join(HERE, "..", "build", "ascon_pynq.bit"))
IP_KEYWORDS = ("ascon_axi", "ascon_aead_hash_axi", "ascon")


class PynqCore:
    """Overlay + MMIO handle for the core; use `open_hw()` for an engine."""

    def __init__(self, bitstream: Optional[str] = None, fclk_mhz: Optional[float] = None, timeout: float = 2.0):
        try:
            from pynq import MMIO, Overlay
        except ImportError as exc:
            raise RuntimeError("pynq is not installed; this transport only runs on the board") from exc
        self.bitstream = bitstream or DEFAULT_BITSTREAM
        if not os.path.exists(self.bitstream):
            raise FileNotFoundError(f"bitstream not found: {self.bitstream} "
                                    "(build it with scripts/build_pynq_overlay.tcl and copy .bit + .hwh)")
        self.overlay = None
        self.ip_name = None
        try:
            self.overlay = Overlay(self.bitstream)
            names = [n for kw in IP_KEYWORDS for n in self.overlay.ip_dict if kw in n.lower()]
            if not names:
                raise RuntimeError(f"no Ascon IP in overlay: {list(self.overlay.ip_dict)}")
            self.ip_name = names[0]
            info = self.overlay.ip_dict[self.ip_name]
            self.base_addr = int(info["phys_addr"])
            self.mmio = MMIO(self.base_addr, int(info.get("addr_range", 0x1000)))
        except Exception as exc:                     # HWH parsing problems: fixed-address fallback
            from pynq import Bitstream
            print(f"[ascon_pynq_driver] Overlay() failed ({exc}); using fixed base 0x{DEFAULT_BASE_ADDR:08x}")
            Bitstream(self.bitstream).download()
            self.base_addr = DEFAULT_BASE_ADDR
            self.mmio = MMIO(self.base_addr, 0x1000)
        if fclk_mhz:
            self.set_fclk(fclk_mhz)
        self.driver = AsconAxiLite(self.mmio, timeout=timeout)

    # ---- PL clock ---------------------------------------------------------
    @staticmethod
    def get_fclk() -> float:
        from pynq.ps import Clocks
        return float(Clocks.fclk0_mhz)

    @staticmethod
    def set_fclk(mhz: float) -> float:
        """Re-program FCLK_CLK0 (the core clock).  The overlay is timed at the
        frequency in scripts/build_pynq_overlay.tcl; higher values are at the
        user's risk and must be validated with the self-test."""
        from pynq.ps import Clocks
        Clocks.fclk0_mhz = mhz
        time.sleep(0.01)
        return float(Clocks.fclk0_mhz)

    def engine(self, use_c: bool = False):
        if use_c:
            from ascon_c import MmioCEngine
            return MmioCEngine(self.base_addr)
        return AxiEngine(self.driver, "hw")


def open_hw(bitstream: Optional[str] = None, fclk_mhz: Optional[float] = None, use_c: bool = False):
    """Load the overlay and return an engine (`hw` Python driver or `hw-c` C loop)."""
    core = PynqCore(bitstream, fclk_mhz)
    eng = core.engine(use_c)
    eng.pynq = core          # keep the overlay alive and reachable
    return eng


def selftest(engine=None) -> bool:
    """Compare the hardware with the reference model on a few vectors."""
    import random
    import ascon
    eng = engine or open_hw()
    rng = random.Random(3)
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    ok = True
    for n in (0, 1, 7, 8, 9, 15, 16, 17, 100, 1000):
        msg = bytes(rng.getrandbits(8) for _ in range(n))
        ok &= eng.hash256(msg) == ascon.ascon_hash(msg)
        for ad_len in (0, 5, 16, 20):
            ad = bytes(rng.getrandbits(8) for _ in range(ad_len))
            ref = ascon.ascon_encrypt(key, nonce, ad, msg)
            ok &= eng.aead_encrypt(key, nonce, ad, msg) == ref
            ok &= eng.aead_decrypt(key, nonce, ad, ref) == msg
    print("hardware selftest:", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    sys.exit(0 if selftest() else 1)
