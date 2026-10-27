import hashlib
import re
import sys


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: solve_pow.py <challenge.html>")
    with open(sys.argv[1], "r", errors="replace") as fh:
        html = fh.read()
    chal = re.search(r'var CHAL_ID = "([0-9a-f]+)";', html)
    diff = re.search(r"var DIFF = (\d+);", html)
    if not chal or not diff:
        sys.exit("could not parse the challenge page")
    cid, bits = chal.group(1), int(diff.group(1))
    nonce = 0
    prefix = "0" * bits
    while True:
        if hashlib.sha1("{}:{}".format(cid, nonce).encode()).hexdigest().startswith(prefix):
            print("{} {} {}".format(cid, nonce, bits))
            return
        nonce += 1


if __name__ == "__main__":
    main()
