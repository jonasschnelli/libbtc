#!/usr/bin/env python
# Copyright (c) 2016 Jonas Schnelli
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys, os
from subprocess import call

valgrind = True;
commands = []
commands.append("-c genkey")
commands.append("-c hdprintkey -p xpub6MR9tbm8V5pGFTQ9hTATxd4kPgdKKqU75ED8s3rddrSknLHgZy1H4Wh596jgoYNH7WNcKEVM1wfKD2pTSdj5Hm7CMJwwyRjHYPQCT2LJXwm")
commands.append("-c pubfrompriv -p L15mEfW7s13utgsTrziK52z6HC1jEZbp3R9ma7qPfwCphhtJFmjp")
commands.append("-c addrfrompub -p 02b905509e4c9bd9b2fc87c95a6e6897f70ee9fd8bd2f1d9dc9a270b62ec11f47e")
commands.append("-c hdgenmaster")
commands.append("-c hdderive -p xpub6MR9tbm8V5pGFTQ9hTATxd4kPgdKKqU75ED8s3rddrSknLHgZy1H4Wh596jgoYNH7WNcKEVM1wfKD2pTSdj5Hm7CMJwwyRjHYPQCT2LJXwm -m m/100h/10h/100/10")


baseCommand = "./bitcointool"
if valgrind == True:
    baseCommand = "valgrind --leak-check=full "+baseCommand
        
for cmd in commands:
    retcode = call(baseCommand+" "+cmd, shell=True)
    if retcode == 1:
        sys.exit(retcode)

sys.exit(os.EX_OK)