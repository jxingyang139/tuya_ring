注：此工具在linux环境运行

python签名加密使用方法：
	例如：将python签名工具放在SDK的build/kernel_sign_tool目录下，未签名加密的文件放在build/build_tmp/cache目录，签名加密后的文件存放在output/bin目录。

	参数说明：
	build/kernel_sign_tool/kernel_sign_tool.py               【签名加密python工具的入口】
	burn_bin                                                                 【签名区分：burn_bin为签名加密业务bin，factory_bin为签名加密产测bin】
	Hi3861_demo 			              【APP名区分】
	0x3F 				              【签名模式：0x0: RSA_V15; 0x1: RSA_PSS ; 0x10 : ECC ; 0x3f : sha256】
	0				              【kernel 版本号：0 ~ 48】
	0				              【boot 版本号：0 ~ 16】
	output/bin/Hi3861_demo_burn.bin                         【签名加密输出路径以及文件名，业务bin与产测bin】
	build/build_tmp/cache/Hi3861_demo_kernel.bin     【未签名加密的路径以及文件名，业务bin与产测bin】
	1				              【flash加密标志，1为不加密，2为加密，加密需要与menuconfig配置保持一致，要么同时配置，要么都不配置】

	业务签名参考：
	python3 build/kernel_sign_tool/kernel_sign_tool.py burn_bin Hi3861_demo 0x3F 0 0 output/bin/Hi3861_demo_burn.bin build/build_tmp/cache/Hi3861_demo_kernel.bin 1

	产测签名参考：
	python3 build/kernel_sign_tool/kernel_sign_tool.py factory_bin Hi3861_demo 0x3F 0 0 output/bin/Hi3861_demo_factory.bin build/build_tmp/cache/Hi3861_demo_kernel_factory.bin 1

	注：python需要依赖工程中的配置，需在工程中使用。