ifeq ($(CONFIG_TARGET_CHIP_HI3861), y)
	ifeq ($(CONFIG_DIAG_SUPPORT), y)
		ifeq ($(CONFIG_QUICK_SEND_MODE)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861/debug/no_mesh_quick_start_mgmt_size_1500
		else ifeq ($(CONFIG_QUICK_SEND_MODE), y)
			LIBPATH += -Lbuild/libs/hi3861/debug/no_mesh_quick_start
		else ifeq ($(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861/debug/mesh_mgmt_size_1500
		else ifeq ($(CONFIG_MESH_SUPPORT), y)
			LIBPATH += -Lbuild/libs/hi3861/debug/mesh
		else ifeq ($(CONFIG_MGMT_FRAME_SIZE_1500), y)
			LIBPATH += -Lbuild/libs/hi3861/debug/no_mesh_mgmt_size_1500
		else
			LIBPATH += -Lbuild/libs/hi3861/debug/no_mesh
		endif
	endif
else
	ifeq ($(CONFIG_DIAG_SUPPORT), y)
		ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y_y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/mesh_pkt_48k_mgmt_size_1500
		else ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MESH_SUPPORT), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/mesh_pkt_48k
		else ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/no_mesh_pkt_48k_mgmt_size_1500
		else ifeq ($(CONFIG_CHIP_PKT_48K), y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/no_mesh_pkt_48k
		else ifeq ($(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/mesh_mgmt_size_1500
		else ifeq ($(CONFIG_MESH_SUPPORT), y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/mesh
		else ifeq ($(CONFIG_MGMT_FRAME_SIZE_1500), y)
			LIBPATH += -Lbuild/libs/hi3861l/debug/no_mesh_mgmt_size_1500
		else
			LIBPATH += -Lbuild/libs/hi3861l/debug/no_mesh
		endif
	endif
endif

ifeq ($(CONFIG_TARGET_CHIP_HI3861), y)
	ifneq ($(CONFIG_DIAG_SUPPORT), y)
		ifeq ($(CONFIG_QUICK_SEND_MODE)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861/release/no_mesh_quick_start_mgmt_size_1500
		else ifeq ($(CONFIG_QUICK_SEND_MODE), y)
			LIBPATH += -Lbuild/libs/hi3861/release/no_mesh_quick_start
		else ifeq ($(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861/release/mesh_mgmt_size_1500
		else ifeq ($(CONFIG_MESH_SUPPORT), y)
			LIBPATH += -Lbuild/libs/hi3861/release/mesh
		else ifeq ($(CONFIG_MGMT_FRAME_SIZE_1500), y)
			LIBPATH += -Lbuild/libs/hi3861/release/no_mesh_mgmt_size_1500
		else
			LIBPATH += -Lbuild/libs/hi3861/release/no_mesh
		endif
	endif
else
	ifneq ($(CONFIG_DIAG_SUPPORT), y)
		ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y_y)
			LIBPATH += -Lbuild/libs/hi3861l/release/mesh_pkt_48k_mgmt_size_1500
		else ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MESH_SUPPORT), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/release/mesh_pkt_48k
		else ifeq ($(CONFIG_CHIP_PKT_48K)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/release/no_mesh_pkt_48k_mgmt_size_1500
		else ifeq ($(CONFIG_CHIP_PKT_48K), y)
			LIBPATH += -Lbuild/libs/hi3861l/release/no_mesh_pkt_48k
		else ifeq ($(CONFIG_MESH_SUPPORT)_$(CONFIG_MGMT_FRAME_SIZE_1500), y_y)
			LIBPATH += -Lbuild/libs/hi3861l/release/mesh_mgmt_size_1500
		else ifeq ($(CONFIG_MESH_SUPPORT), y)
			LIBPATH += -Lbuild/libs/hi3861l/release/mesh
		else ifeq ($(CONFIG_MGMT_FRAME_SIZE_1500), y)
			LIBPATH += -Lbuild/libs/hi3861l/release/no_mesh_mgmt_size_1500
		else
			LIBPATH += -Lbuild/libs/hi3861l/release/no_mesh
		endif
	endif
endif

ifeq ($(CONFIG_HILINK), y)
	LIBPATH += -Lcomponents/hilink/lib
endif

ifeq ($(CONFIG_OHOS), y)
	LIBPATH += -Lcomponents/OHOS/ndk/libs
endif