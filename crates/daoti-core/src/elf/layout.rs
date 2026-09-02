//! 内存段布局规划（L0-2）
//!
//! 接收 L0-1 解析的 ELF 加载段（`ElfSegment`，仅 PT_LOAD），
//! 规划其在沙箱地址空间中的映射：页对齐、排序、重叠检测、BSS 零区统计。
//!
//! 输出的 `MemoryLayout` 是 L0-3 syscall 拦截桩和真实加载器的内存地图。

use daoti_common::DaotiError;

use super::{ElfSegment, PT_LOAD};

/// 页大小：x86_64 Linux 用户空间默认 4 KiB
pub const PAGE_SIZE: u64 = 4096;

/// 单个段在沙箱内的映射计划
#[derive(Debug, Clone, PartialEq)]
pub struct SegmentMapping {
    /// 段在沙箱内的起始偏移（相对沙箱基址，页对齐）
    pub offset_in_sandbox: u64,
    /// 段原始虚拟地址（ELF 头中的 vaddr）
    pub vaddr: u64,
    /// 文件部分大小（页对齐后的占用）
    pub filesz_pages: u64,
    /// 映射后内存大小（含 BSS 零区，页对齐）
    pub memsz_pages: u64,
    /// 段标志（PF_R=4, PF_W=2, PF_X=1）
    pub flags: u32,
    /// 是否需要 BSS 零填充（filesz < memsz）
    pub has_bss: bool,
    /// 文件实际大小（未对齐，原始值）
    pub raw_filesz: u64,
    /// 内存实际大小（未对齐，原始值）
    pub raw_memsz: u64,
}

/// 沙箱内存布局总览
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryLayout {
    /// 页大小
    pub page_size: u64,
    /// 沙箱基址（虚拟地址，页对齐）
    pub base: u64,
    /// 沙箱总大小（页对齐）
    pub total_size: u64,
    /// 各段映射计划（按 vaddr 升序）
    pub mappings: Vec<SegmentMapping>,
    /// 沙箱内 BSS 零填充总量（字节）
    pub bss_bytes: u64,
    /// PT_LOAD 段数量
    pub load_segment_count: usize,
}

/// 向下取整到页边界
pub fn align_down(addr: u64, page: u64) -> u64 {
    addr - (addr % page)
}

/// 向上取整到页边界
pub fn align_up(addr: u64, page: u64) -> u64 {
    if page == 0 {
        return addr;
    }
    let rem = addr % page;
    if rem == 0 {
        addr
    } else {
        addr + (page - rem)
    }
}

/// 规划 PT_LOAD 段在沙箱内的内存布局
///
/// 规则：
/// 1. 仅处理 `PT_LOAD` 段，其余忽略；
/// 2. 段按 vaddr 升序排列；
/// 3. 每个段起点向下页对齐、终点向上页对齐；
/// 4. 排序后若相邻段发生重叠则返回错误；
/// 5. 没有 PT_LOAD 段或列表为空返回错误（不可执行）。
pub fn plan_segments(segments: &[ElfSegment]) -> Result<MemoryLayout, DaotiError> {
    // 1. 过滤并排序 PT_LOAD
    let mut loads: Vec<&ElfSegment> = segments.iter().filter(|s| s.type_ == PT_LOAD).collect();
    loads.sort_by_key(|s| s.vaddr);

    if loads.is_empty() {
        return Err(DaotiError::Other(
            "ELF 无可加载段（PT_LOAD 数量为 0），无法规划内存布局".into(),
        ));
    }

    // 2. 逐段规划（同时做重叠检测）
    let mut mappings: Vec<SegmentMapping> = Vec::with_capacity(loads.len());
    let mut prev_raw_end: Option<u64> = None; // 上一段未对齐的实际终点
    let mut bss_bytes: u64 = 0;

    for seg in &loads {
        let start_aligned = align_down(seg.vaddr, PAGE_SIZE);
        let filesz_aligned = align_up(seg.filesz, PAGE_SIZE);
        let memsz_end = seg
            .vaddr
            .saturating_add(seg.memsz)
            .max(seg.vaddr + filesz_aligned);
        let end_aligned = align_up(memsz_end, PAGE_SIZE);

        if let Some(prev_end) = prev_raw_end {
            if seg.vaddr < prev_end {
                return Err(DaotiError::Other(format!(
                    "段重叠：段 vaddr=0x{:x} 早于上一段实际终点 0x{:x}",
                    seg.vaddr, prev_end
                )));
            }
        }

        let seg_filesz = seg.filesz.max(filesz_aligned);
        let bss = seg.memsz > seg.filesz;
        if bss {
            bss_bytes += seg.memsz.saturating_sub(seg.filesz);
        }

        mappings.push(SegmentMapping {
            offset_in_sandbox: start_aligned,
            vaddr: seg.vaddr,
            filesz_pages: seg_filesz,
            memsz_pages: end_aligned.saturating_sub(start_aligned),
            flags: seg.flags,
            has_bss: bss,
            raw_filesz: seg.filesz,
            raw_memsz: seg.memsz,
        });

        prev_raw_end = Some(seg.vaddr.saturating_add(seg.memsz));
    }

    // 3. 计算沙箱基址与总大小
    let base = mappings.first().map(|m| m.offset_in_sandbox).unwrap_or(0);
    let last_end = mappings
        .last()
        .map(|m| m.offset_in_sandbox + m.memsz_pages)
        .unwrap_or(0);
    let total_size = last_end.saturating_sub(base);

    Ok(MemoryLayout {
        page_size: PAGE_SIZE,
        base,
        total_size,
        mappings,
        bss_bytes,
        load_segment_count: loads.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::{ElfSegment, PF_R, PF_W, PF_X};

    fn seg(type_: u32, vaddr: u64, filesz: u64, memsz: u64, flags: u32) -> ElfSegment {
        ElfSegment {
            type_,
            offset: 0,
            vaddr,
            paddr: vaddr,
            filesz,
            memsz,
            flags,
            align: PAGE_SIZE,
        }
    }

    #[test]
    fn test_plan_single_load_segment() {
        // 单个 PT_LOAD：入口 0x400000，1 页
        let se = seg(PT_LOAD, 0x400000, 100, 100, PF_R | PF_X);
        let layout = plan_segments(&[se]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        assert_eq!(layout.base, 0x400000);
        assert_eq!(layout.total_size, PAGE_SIZE);
        assert_eq!(layout.load_segment_count, 1);
        assert_eq!(layout.mappings.len(), 1);
        let m = &layout.mappings[0];
        assert_eq!(m.offset_in_sandbox, 0x400000);
        assert_eq!(m.filesz_pages, PAGE_SIZE);
        assert_eq!(m.memsz_pages, PAGE_SIZE);
        assert!(!m.has_bss);
        assert_eq!(layout.bss_bytes, 0);
    }

    #[test]
    fn test_plan_two_segments_sorted_by_vaddr() {
        // 两个段顺序传入被打乱，应自动按 vaddr 排序
        let text = seg(PT_LOAD, 0x400000, 100, 100, PF_R | PF_X);
        let data = seg(PT_LOAD, 0x600000, 50, 200, PF_R | PF_W);
        let layout = plan_segments(&[data, text]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        assert_eq!(layout.mappings.len(), 2);
        assert_eq!(layout.mappings[0].vaddr, 0x400000, "应按 vaddr 升序");
        assert_eq!(layout.mappings[1].vaddr, 0x600000);
        // 两段相距 0x200000，各自 1 页 → 总大小 = 0x200000 + 4096
        assert_eq!(layout.total_size, 0x200000 + PAGE_SIZE);
    }

    #[test]
    fn test_plan_recognizes_bss_region() {
        // filesz=50 < memsz=4096+ → BSS 零区
        let se = seg(PT_LOAD, 0x600000, 50, 5000, PF_R | PF_W);
        let layout = plan_segments(&[se]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        assert!(layout.mappings[0].has_bss);
        assert_eq!(layout.bss_bytes, 5000 - 50);
        // memsz_pages 应覆盖 5000 字节 → 2 页
        assert_eq!(layout.mappings[0].memsz_pages, 2 * PAGE_SIZE);
    }

    #[test]
    fn test_plan_rejects_empty_segments() {
        let err = plan_segments(&[]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("无可加载段"), "应提示无可加载段，得到：{msg}");
    }

    #[test]
    fn test_plan_ignores_non_load_segments() {
        // 只含 PT_NULL → 无可加载段
        let se = seg(0, 0, 0, 0, 0); // PT_NULL
        let err = plan_segments(&[se]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("无可加载段"), "PT_NULL 应被过滤，得到：{msg}");
    }

    #[test]
    fn test_plan_rejects_overlapping_segments() {
        // 两段真重叠：第二段起点 0x400800 落在第一段 [0x400000, 0x401000) 内部
        let a = seg(PT_LOAD, 0x400000, 4096, 4096, PF_R | PF_X);
        let b = seg(PT_LOAD, 0x400800, 4096, 4096, PF_R | PF_W); // 与 a 重叠
        let err = plan_segments(&[a, b]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("段重叠"), "应提示段重叠，得到：{msg}");
    }

    #[test]
    fn test_plan_allows_adjacent_segments() {
        // 两段恰好相接（b 起点 = a 终点）不是重叠，应放行
        let a = seg(PT_LOAD, 0x400000, 4096, 4096, PF_R | PF_X);
        let b = seg(PT_LOAD, 0x401000, 4096, 4096, PF_R | PF_W);
        let layout = plan_segments(&[a, b]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        assert_eq!(layout.mappings.len(), 2);
        assert_eq!(layout.total_size, 2 * PAGE_SIZE);
    }

    #[test]
    fn test_plan_aligns_partial_page() {
        // 段起点未页对齐：起点向下取整、终点向上取整 → 占用 2 页
        let se = seg(PT_LOAD, 0x401234, 100, 100, PF_R | PF_X);
        let layout = plan_segments(&[se]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        // 起点向下取整到 0x401000
        assert_eq!(layout.base, 0x401000);
        // 终点 0x401234+0x1000=0x402234 向上到 0x403000 → 2 页
        assert_eq!(layout.total_size, 2 * PAGE_SIZE);
    }

    #[test]
    fn test_align_up_down() {
        assert_eq!(align_down(0x401234, PAGE_SIZE), 0x401000);
        assert_eq!(align_up(0x401234, PAGE_SIZE), 0x402000);
        assert_eq!(align_up(0x401000, PAGE_SIZE), 0x401000);
        assert_eq!(align_down(0x400000, PAGE_SIZE), 0x400000);
    }

    #[test]
    fn test_plan_bss_mem_greater_than_1_page() {
        // memsz 3 页、filesz 1 页 → memsz_pages 3 页
        let se = seg(PT_LOAD, 0x600000, 4096, 3 * 4096, PF_R | PF_W);
        let layout = plan_segments(&[se]).unwrap_or_else(|e| panic!("规划失败：{e}"));
        assert_eq!(layout.mappings[0].memsz_pages, 3 * PAGE_SIZE);
        assert_eq!(layout.bss_bytes, 2 * PAGE_SIZE);
    }
}
