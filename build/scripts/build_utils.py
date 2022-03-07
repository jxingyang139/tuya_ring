#!/usr/bin/env python3
# coding=utf-8

'''
* Copyright (c) 2020 HiSilicon (Shanghai) Technologies CO., LIMITED.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Description: Utilities of building system.
'''

import subprocess

__init__ = ['shell']

def shell(cmdlist, logfile=None):
    print("Command:", cmdlist)
    try:
        subp = subprocess.Popen(cmdlist, shell=False, stdout=subprocess.PIPE, encoding="utf-8")
        while True:
            output = subp.stdout.readline()
            if output == '' and subp.poll() is not None:
                break
            if output:
                print(output.strip())
                if logfile is not None:
                    logfile.write(output)
        return subp.returncode
    except Exception as err:
        print(err)
        if logfile is not None:
            logfile.write(str(err))
        return -1
