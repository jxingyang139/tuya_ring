#!/bin/bash
#
# Copyright (c) 2020 HiSilicon (Shanghai) Technologies CO., LIMITED.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Description: Menuconfig entry
#
set -e
CROOT=$(pwd)

build_uboot_patch() {
	if [ ! -d $CROOT/third_party/u-boot-2020.01/u-boot-2020.01/ ]; then
		tar -xf u-boot-2020.01.tar.bz2
		cd u-boot-2020.01
		patch -p1 < ./../hisilicon_patch/hisilicon-u-boot-2020.01.patch
	fi
}
