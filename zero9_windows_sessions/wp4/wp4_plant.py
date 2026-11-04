#!/usr/bin/env python3
# wp4_plant.py - plant a sess_<sid> link under the FILTERED (non-elevated) token.
# usage: wp4_plant.py hardlink|symlink <link_winpath> <target_winpath>
# Default invocation re-execs itself through `runas /trustlevel:0x20000` so the
# actual link creation happens with a token holding ONLY SeChangeNotifyPrivilege
# (no SeCreateSymbolicLinkPrivilege, no admin). With --direct it plants in the
# current token (used by the re-exec child).
import os, subprocess, sys, time

def main():
    mode, link, target = sys.argv[1], sys.argv[2], sys.argv[3]
    if "--direct" in sys.argv:
        if mode == "hardlink":
            os.link(target, link)          # target must exist (hard link)
        elif mode == "symlink":
            os.symlink(target, link)       # target may dangle (python passes
                                           # SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
        else:
            raise SystemExit("bad mode")
        line = "%s PLANTED-DIRECT user=%s mode=%s link=%s target=%s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), os.getlogin(), mode, link, target)
        # receipt written BY THE FILTERED-TOKEN PROCESS itself
        receipt = os.path.join(os.path.dirname(os.path.abspath(__file__)), "receipts", "plant_receipts.log")
        os.makedirs(os.path.dirname(receipt), exist_ok=True)
        with open(receipt, "a") as f:
            f.write(line)
        print("PLANTED-DIRECT %s %s -> %s" % (mode, link, target))
        return
    # spawn under the filtered token; caller polls for the link to appear
    me = os.path.abspath(__file__)
    subprocess.run(
        ["runas", "/trustlevel:0x20000",
         '"%s" "%s" %s "%s" "%s" --direct' % (sys.executable, me, mode, link, target)],
        check=False)

if __name__ == "__main__":
    main()
