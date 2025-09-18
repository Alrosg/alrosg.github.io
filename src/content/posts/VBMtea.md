---
title: VBMeta分区校验机制的技术原理
published: 2025-09-11
pinned: false
description: Android AVB 机制与禁用原理
tags: [Android, 底层分区,AVB]
category: 技术
author: 洛水
draft: false
date: 2025-09-10
pubDate: 2025-09-11
---

# VBMeta 分区校验机制的技术原理深度解析

## 一、AVB 架构中的 VBMeta 角色与功能

在 **Android Verified Boot (AVB)** 安全架构中，**VBMeta 分区**承担着验证链核心组件的角色。该分区存储了采用 **ASN.1 DER** 编码的验证数据，主要包括：

-  **加密哈希值**：使用 **SHA-256** 或 **SHA-512** 算法计算的关键分区摘要
-  **RSA-2048/RSA-4096 签名**：基于 **PKI 体系**的数字签名  
-  **描述符元数据**：分区大小、偏移量等结构信息

这些数据共同构成了 Android 启动时的验证基础，确保系统组件从 **bootloader** 到 **system 分区**的完整性和真实性。

## 二、Fastboot 禁用校验的底层机制

通过分析 **AOSP 源码**，可以发现 Fastboot 实现校验禁用的核心机制在于修改 VBMeta 镜像中的特定数据位。

### 1. 数据结构定位

// 源自 avb_vbmeta_image.h

typedef struct AvbVBMetaImageHeader {

uint8_t magic[4]; // 'AVB0' 魔数 (偏移 0x00)

uint32_t required_libavb_version_major; // 主版本号 (偏移 0x04)

uint32_t required_libavb_version_minor; // 次版本号 (偏移 0x08)

uint64_t authentication_data_block_size; // 认证数据块大小 (偏移 0x10)

uint64_t auxiliary_data_block_size; // 辅助数据块大小 (偏移 0x18)

uint32_t algorithm_type; // 算法类型 (偏移 0x20)

uint64_t hash_offset; // 哈希偏移 (偏移 0x28)

uint64_t hash_size; // 哈希大小 (偏移 0x30)

uint64_t signature_offset; // 签名偏移 (偏移 0x38)

uint64_t signature_size; // 签名大小 (偏移 0x40)

uint64_t public_key_offset; // 公钥偏移 (偏移 0x48)

uint64_t public_key_size; // 公钥大小 (偏移 0x50)

uint64_t public_key_metadata_offset; // 公钥元数据偏移 (偏移 0x58)

uint64_t public_key_metadata_size; // 公钥元数据大小 (偏移 0x60)

uint64_t descriptors_offset; // 描述符偏移 (偏移 0x68)

uint64_t descriptors_size; // 描述符大小 (偏移 0x70)

uint64_t rollback_index; // 回滚索引 (偏移 0x78)

uint32_t flags; // 标志位 (偏移 0x80/128 十进制)

uint32_t rollback_index_location; // 回滚索引位置 (偏移 0x84/132 十进制)

uint8_t release_string[48]; // 发布字符串 (偏移 0x88/136 十进制)

} AVB_ATTR_PACKED AvbVBMetaImageHeader;

### 2. 关键标志位修改

根据 AVB 规范，`flags` 字段 (偏移 **128 字节**) 采用**大端序编码**，其二进制结构如下：

**位布局 (大端序)**：
字节 130 (0x82)：`[保留位7][保留位6][保留位5][保留位4][保留位3][保留位2][禁用验证位][禁用哈希树位]`

**具体位操作**：

-  **第 0 位 (LSB)**：控制 `AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED`
  - 置 `1`：禁用 **dm-verity 哈希树验证**
  - 置 `0`：启用哈希树验证

-  **第 1 位**：控制 `AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED`
  - 置 `1`：禁用**签名验证**和**描述符解析**
  - 置 `0`：启用完整验证

### 3. 修改语义分析

当同时禁用两项校验时，`flags` 字段的二进制值为：
`00000000 00000000 00000000 00000011`

对应大端序十六进制值：**`0x00000003`**

这种修改导致：

1.  **启动时跳过哈希验证**：内核不再验证系统分区的 dm-verity 哈希树
2.  **跳过签名验证**：bootloader 不验证 VBMeta 本身的数字签名
3.  **描述符解析禁用**：AVB 描述符链解析过程被短路

## 三、技术实现约束与边界条件

### 1. 字节序处理要求

由于 `flags` 字段采用**网络字节序 (大端序)**，修改时必须遵循：

uint32_t flags = ntohl((uint32_t)(data + 128));

flags |= (disable_verity ? 0x00000001 : 0) | (disable_verification ? 0x00000002 : 0);

(uint32_t)(data + 128) = htonl(flags);

### 2. 验证流程影响

修改后的启动流程变化：

| 验证阶段 | 原始流程 | 修改后流程 |
|---------|---------|-----------|
| **VBMeta 签名验证** | RSA-2048/PSS 验证 |  跳过验证 |
| **描述符解析** | 完整解析所有描述符 |  终止解析 |
| **哈希树验证** | 逐块验证 dm-verity 哈希 |  跳过验证 |
| **启动状态** |  完整验证链 |  最小验证路径 |

### 3. 安全语义保持

这种修改保持了 AVB 架构的完整性：

-  修改仅影响验证严格性，不改变数据格式
-  所有密码学原语保持不变 (SHA-256、RSA 等)
-  回滚索引机制继续有效
-  硬件级安全启动 (如 TrustZone) 不受影响

## 四、技术原理总结

VBMeta 校验禁用本质是通过修改特定内存位置的标志位来改变 AVB 验证流程的严格性。这种修改具有以下特点：

1.  **位置精确**：针对偏移 128 字节处的 32 位 `flags` 字段
2.  **位操作明确**：第 0 位控制哈希树验证，第 1 位控制签名验证
3.  **语义清晰**：符合 AVB 规范定义的标志位语义
4.  **架构兼容**：不破坏 VBMeta 的整体结构和数据完整性

这种基于**二进制精确修改**的方法，为系统调试和开发提供了在保持 AVB 架构前提下的灵活性，是**安全性与可用性之间的精心平衡**。

**根据以上原理，我制作了一个在线禁用AVB验证的web工具，感兴趣可以访问**[VBMetme 工具](https://alrosg.fdns.fun/vbmeta-tool/)