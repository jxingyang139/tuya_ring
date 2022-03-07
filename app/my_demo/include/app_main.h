/*
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
 */

#ifndef __APP_MAIN_H__
#define __APP_MAIN_H__

#include <hi_types_base.h>
#ifdef CONFIG_OHOS
#include <wifi_error_code.h>
#include "hos_init.h"
#endif

typedef struct {
    hi_u16 gpio6_cfg;
    hi_u16 gpio8_cfg;
    hi_u16 gpio10_cfg;
    hi_u16 gpio11_cfg;
    hi_u16 gpio12_cfg;
    hi_u16 gpio13_cfg;
    hi_u16 sfc_csn_cfg;
} app_iocfg_backup;

#ifdef CONFIG_OHOS
#define SYS_NAME(name, step) ".zinitcall.sys." #name #step ".init"
#define MODULE_NAME(name, step) ".zinitcall." #name #step ".init"

#define sys_call(name, step)                                      \
    do {                                                          \
        InitCall *initcall = (InitCall *)(sys_begin(name, step)); \
        InitCall *initend = (InitCall *)(sys_end(name, step));    \
        for (; initcall < initend; initcall++) {                  \
            (*initcall)();                                        \
        }                                                         \
    } while (0)

#define module_call(name, step)                                      \
    do {                                                             \
        InitCall *initcall = (InitCall *)(module_begin(name, step)); \
        InitCall *initend = (InitCall *)(module_end(name, step));    \
        for (; initcall < initend; initcall++) {                     \
            (*initcall)();                                           \
        }                                                            \
    } while (0)

#if (defined(__GNUC__) || defined(__clang__))

#define sys_begin(name, step)                                 \
    ({        extern InitCall __zinitcall_sys_##name##_start;       \
        InitCall *initCall = &__zinitcall_sys_##name##_start; \
        (initCall);                                           \
    })

#define sys_end(name, step)                                 \
    ({        extern InitCall __zinitcall_sys_##name##_end;       \
        InitCall *initCall = &__zinitcall_sys_##name##_end; \
        (initCall);                                         \
    })

#define module_begin(name, step)                          \
    ({        extern InitCall __zinitcall_##name##_start;       \
        InitCall *initCall = &__zinitcall_##name##_start; \
        (initCall);                                       \
    })
#define module_end(name, step)                          \
    ({        extern InitCall __zinitcall_##name##_end;       \
        InitCall *initCall = &__zinitcall_##name##_end; \
        (initCall);                                     \
    })

#define module_sys_init(name)     \
    do {                   \
        sys_call(name, 0); \
    } while (0)

#define module_init(name)     \
    do {                      \
        module_call(name, 0); \
    } while (0)

#define init_test_call()      \
    do {                      \
        module_call(test, 0); \
    } while (0)

#else

#define sys_begin(name, step) __section_begin(SYS_NAME(name, step))
#define sys_end(name, step) __section_end(SYS_NAME(name, step))
#define module_begin(name, step) __section_begin(MODULE_NAME(name, step))
#define module_end(name, step) __section_end(MODULE_NAME(name, step))

#pragma section = SYS_NAME(service, 0)
#pragma section = SYS_NAME(service, 1)
#pragma section = SYS_NAME(service, 2)
#pragma section = SYS_NAME(service, 3)
#pragma section = SYS_NAME(service, 4)
#pragma section = SYS_NAME(feature, 0)
#pragma section = SYS_NAME(feature, 1)
#pragma section = SYS_NAME(feature, 2)
#pragma section = SYS_NAME(feature, 3)
#pragma section = SYS_NAME(feature, 4)
#pragma section = MODULE_NAME(bsp, 0)
#pragma section = MODULE_NAME(bsp, 1)
#pragma section = MODULE_NAME(bsp, 2)
#pragma section = MODULE_NAME(bsp, 3)
#pragma section = MODULE_NAME(bsp, 4)
#pragma section = MODULE_NAME(device, 0)
#pragma section = MODULE_NAME(device, 1)
#pragma section = MODULE_NAME(device, 2)
#pragma section = MODULE_NAME(device, 3)
#pragma section = MODULE_NAME(device, 4)
#pragma section = MODULE_NAME(core, 0)
#pragma section = MODULE_NAME(core, 1)
#pragma section = MODULE_NAME(core, 2)
#pragma section = MODULE_NAME(core, 3)
#pragma section = MODULE_NAME(core, 4)
#pragma section = MODULE_NAME(run, 0)
#pragma section = MODULE_NAME(run, 1)
#pragma section = MODULE_NAME(run, 2)
#pragma section = MODULE_NAME(run, 3)
#pragma section = MODULE_NAME(run, 4)

#define module_sys_init(name)     \
    do {                   \
        sys_call(name, 0); \
        sys_call(name, 1); \
        sys_call(name, 2); \
        sys_call(name, 3); \
        sys_call(name, 4); \
    } while (0)

#define module_init(name)     \
    do {                      \
        module_call(name, 0); \
        module_call(name, 1); \
        module_call(name, 2); \
        module_call(name, 3); \
        module_call(name, 4); \
    } while (0)
#endif

extern void NetCfgSampleBiz(void);
WifiErrorCode InitWifiGlobalLock(void);
#endif

#endif // __APP_MAIN_H__
