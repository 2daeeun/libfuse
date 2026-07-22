#!/usr/bin/env python3

import subprocess
from os.path import join as pjoin

from util import basename


def test_extfuse_init():
    subprocess.check_call([pjoin(basename, 'test', 'test_extfuse_init')])
