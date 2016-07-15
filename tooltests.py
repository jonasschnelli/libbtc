#!/usr/bin/env python
# Copyright (c) 2016 Jonas Schnelli
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys, os
from subprocess import call

valgrind = True;
commands = []
commands.append(["-v", 0])
commands.append(["-foobar", 1])
commands.append(["-c genkey", 0])
commands.append(["-c genkey --testnet", 0])
commands.append(["-c genkey --regtest", 0])
commands.append(["", 1])
commands.append(["-c hdprintkey", 1])
commands.append(["-c hdprintkey -p xpub6MR9tbm8V5pGFTQ9hTATxd4kPgdKKqU75ED8s3rddrSknLHgZy1H4Wh596jgoYNH7WNcKEVM1wfKD2pTSdj5Hm7CMJwwyRjHYPQCT2LJXwm", 0])
commands.append(["-c hdprintkey -p tprv8ZgxMBicQKsPegfnEE6sgR64tuPn72fX965MeazaJC72Sfi5JfqLrCnQmA9vTJTCxfDpiq2jWBSLc8L2Uy497ij5iT4KDvXYZRWxCNWPugm", 1])
commands.append(["-c hdprintkey -p tprv8ZgxMBicQKsPegfnEE6sgR64tuPn72fX965MeazaJC72Sfi5JfqLrCnQmA9vTJTCxfDpiq2jWBSLc8L2Uy497ij5iT4KDvXYZRWxCNWPugm --testnet", 0])
commands.append(["-c pubfrompriv -p L15mEfW7s13utgsTrziK52z6HC1jEZbp3R9ma7qPfwCphhtJFmjp", 0]) #successfull WIF to pub
commands.append(["-c pubfrompriv -p L15mEfW7s13utgsTrziK52z6HC1jEZbp3R9", 1]) #invalid WIF key
commands.append(["-c addrfrompub -p 02b905509e4c9bd9b2fc87c95a6e6897f70ee9fd8bd2f1d9dc9a270b62ec11f47e", 1])
commands.append(["-c addrfrompub -k 02b905509e4c9bd9b2fc87c95a6e6897f70ee9fd8bd2f1d9dc9a270b62ec11f47e", 0])
commands.append(["-c hdgenmaster", 0])
commands.append(["-c hdderive -p xpub6MR9tbm8V5pGFTQ9hTATxd4kPgdKKqU75ED8s3rddrSknLHgZy1H4Wh596jgoYNH7WNcKEVM1wfKD2pTSdj5Hm7CMJwwyRjHYPQCT2LJXwm -m m/100h/10h/100/10", 0])
commands.append(["-c hdderive", 1]) #missing key
commands.append(["-c hdderive -p xpub6MR9tbm8V5pGFTQ9hTATxd4kPgdKKqU75ED8s3rddrSknLHgZy1H4Wh596jgoYNH7WNcKEVM1wfKD2pTSdj5Hm7CMJwwyRjHYPQCT2LJXwm", 1]) #missing keypath


baseCommand = "./bitcointool"
if valgrind == True:
    baseCommand = "valgrind --leak-check=full "+baseCommand

errored = False
for cmd in commands:
    retcode = call(baseCommand+" "+cmd[0], shell=True)
    if retcode != cmd[1]:
        print("ERROR during "+cmd[0])
        sys.exit(os.EX_DATAERR)

sys.exit(os.EX_OK)