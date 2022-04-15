#!/usr/bin/env python
from googlesearch import search
import sys


if len(sys.argv) != 2:
  print("Usage: {} <dork>")
  sys.exit(-1)

for url in search(sys.argv[1], stop=1000):
  print(url)
