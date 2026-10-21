/* linux/arch/arm/plat-s5p/bootmem.c
 *
 * Copyright (c) 2009 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * Bootmem helper functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/err.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <asm/setup.h>
#include <asm/cacheflush.h>
#include <linux/io.h>
#include <mach/memory.h>
#include <plat/media.h>
#include <mach/media.h>

static struct s5p_media_device *media_devs;
static int nr_media_devs;

static dma_addr_t media_base[NR_BANKS];

#ifdef CONFIG_S5P_MEDIA_CMA
#define MEDIA_CMA_ALIGN		(PAGE_SIZE << (MAX_ORDER - 1))

static bool s5p_media_shared(struct s5p_media_device *mdev)
{
	return mdev->id == S5P_MDEV_MFC || mdev->id == S5P_MDEV_FIMC0 ||
		mdev->id == S5P_MDEV_FIMC2;
}
#endif

static struct s5p_media_device *s5p_get_media_device(int dev_id, int bank)
{
	struct s5p_media_device *mdev = NULL;
	int i = 0, found = 0;

	if (dev_id < 0)
		return NULL;

	while (!found && (i < nr_media_devs)) {
		mdev = &media_devs[i];
		if (mdev->id == dev_id && mdev->bank == bank)
			found = 1;
		else
			i++;
	}

	if (!found)
		mdev = NULL;

	return mdev;
}

dma_addr_t s5p_get_media_memory_bank(int dev_id, int bank)
{
	struct s5p_media_device *mdev;

	mdev = s5p_get_media_device(dev_id, bank);
	if (!mdev) {
		printk(KERN_ERR "invalid media device\n");
		return 0;
	}

	if (!mdev->paddr) {
		printk(KERN_ERR "no memory for %s\n", mdev->name);
		return 0;
	}

	return mdev->paddr;
}
EXPORT_SYMBOL(s5p_get_media_memory_bank);

size_t s5p_get_media_memsize_bank(int dev_id, int bank)
{
	struct s5p_media_device *mdev;

	mdev = s5p_get_media_device(dev_id, bank);
	if (!mdev) {
		printk(KERN_ERR "invalid media device\n");
		return 0;
	}

	return mdev->memsize;
}
EXPORT_SYMBOL(s5p_get_media_memsize_bank);

dma_addr_t s5p_get_media_membase_bank(int bank)
{
	if (bank > meminfo.nr_banks) {
		printk(KERN_ERR "invalid bank.\n");
		return -EINVAL;
	}

	return media_base[bank];
}
EXPORT_SYMBOL(s5p_get_media_membase_bank);

void s5p_reserve_bootmem(struct s5p_media_device *mdevs,
			 int nr_mdevs, size_t boundary)
{
	struct s5p_media_device *mdev;
	u64 start, end;
	int i, ret;
	dma_addr_t mfc_paddr;

	media_devs = mdevs;
	nr_media_devs = nr_mdevs;

	for (i = 0; i < meminfo.nr_banks; i++)
		media_base[i] = meminfo.bank[i].start + meminfo.bank[i].size;

	for (i = 0; i < nr_media_devs; i++) {
		mdev = &media_devs[i];
		if (mdev->memsize <= 0)
			continue;

		if (!strcmp(mdev->name, "jpeg"))
			mdev->paddr = mfc_paddr;
		else
		if (!mdev->paddr) {
			size_t size = mdev->memsize;
			size_t align = PAGE_SIZE;

			start = meminfo.bank[mdev->bank].start;
			end = start + meminfo.bank[mdev->bank].size;

			if (boundary && (boundary < end - start))
				start = end - boundary;

#ifdef CONFIG_S5P_MEDIA_CMA
			if (s5p_media_shared(mdev)) {
				size = ALIGN(size, MEDIA_CMA_ALIGN);
				align = MEDIA_CMA_ALIGN;
			}
#endif
			mdev->paddr = memblock_find_in_range(start, end,
						size, align);
		}

#ifdef CONFIG_S5P_MEDIA_CMA
		if (s5p_media_shared(mdev)) {
			mdev->cma_size = ALIGN(mdev->memsize, MEDIA_CMA_ALIGN);
			ret = memblock_reserve(mdev->paddr, mdev->cma_size);
		} else if (mdev->id == S5P_MDEV_JPEG)
			ret = 0;
		else
#endif
		ret = memblock_remove(mdev->paddr, mdev->memsize);
		if (ret < 0)
			pr_err("memblock_reserve(%x, %x) failed\n",
				mdev->paddr, mdev->memsize);

		if (media_base[mdev->bank] > mdev->paddr)
			media_base[mdev->bank] = mdev->paddr;

		if (!strcmp(mdev->name, "mfc") && mdev->bank == 0)
			mfc_paddr = mdev->paddr;

		printk(KERN_INFO "s5p: %lu bytes system memory reserved "
			"for %s at 0x%08x, %d-bank base(0x%08x)\n",
			(unsigned long) mdev->memsize, mdev->name, mdev->paddr,
			mdev->bank, media_base[mdev->bank]);
	}
}

#ifdef CONFIG_S5P_MEDIA_CMA
static DEFINE_MUTEX(s5p_media_cma_lock);

static struct s5p_media_device *s5p_media_cma_device(int dev_id, int bank)
{
	struct s5p_media_device *mdev;

	if (dev_id == S5P_MDEV_JPEG) {
		dev_id = S5P_MDEV_MFC;
		bank = 0;
	}

	mdev = s5p_get_media_device(dev_id, bank);
	if (!mdev || !mdev->cma_size)
		return NULL;

	return mdev;
}

int s5p_media_get(int dev_id, int bank)
{
	struct s5p_media_device *mdev = s5p_media_cma_device(dev_id, bank);
	unsigned long pfn, start = jiffies;
	unsigned int ms;
	int ret = 0, tries = 0;
	void *vaddr;

	if (!mdev)
		return 0;

	mutex_lock(&s5p_media_cma_lock);

	if (mdev->users++)
		goto out;

	pfn = __phys_to_pfn(mdev->paddr);
	while ((ret = alloc_contig_range(pfn, pfn +
			(mdev->cma_size >> PAGE_SHIFT), MIGRATE_CMA))) {
		if (ret == -EINTR ||
		    time_after(jiffies, start + msecs_to_jiffies(1500)))
			break;
		tries++;
		msleep(50);
	}

	ms = jiffies_to_msecs(jiffies - start);
	if (ret) {
		unsigned long i, busy = 0;

		mdev->users--;
		pr_err("s5p: %s can't get its %u KB back: %d, %u ms\n",
			mdev->name, mdev->cma_size >> 10, ret, ms);
		for (i = 0; i < mdev->cma_size >> PAGE_SHIFT; i++) {
			struct page *page = pfn_to_page(pfn + i);
			struct address_space *mapping;

			if (PageBuddy(page) || !page_count(page))
				continue;
			if (busy++ >= 8)
				continue;
			mapping = page_mapping(page);
			pr_err("s5p: pfn %lx flags %lx count %d mapcount %d "
				"lru %d %s ino %lu readpage %pf migrate %pf\n",
				pfn + i, page->flags, page_count(page),
				page_mapcount(page), PageLRU(page),
				mapping && mapping->host ?
					mapping->host->i_sb->s_type->name : "-",
				mapping && mapping->host ?
					mapping->host->i_ino : 0,
				mapping ? mapping->a_ops->readpage : NULL,
				mapping ? mapping->a_ops->migratepage : NULL);
		}
		pr_err("s5p: %lu pages in use\n", busy);
		goto out;
	}

	vaddr = phys_to_virt(mdev->paddr);
	dmac_flush_range(vaddr, vaddr + mdev->cma_size);
	outer_flush_range(mdev->paddr, mdev->paddr + mdev->cma_size);

	if (ms >= 100)
		pr_info("s5p: %s got its %u KB back in %u ms, %d retries\n",
			mdev->name, mdev->cma_size >> 10, ms, tries);
out:
	mutex_unlock(&s5p_media_cma_lock);
	return ret;
}
EXPORT_SYMBOL(s5p_media_get);

void s5p_media_put(int dev_id, int bank)
{
	struct s5p_media_device *mdev = s5p_media_cma_device(dev_id, bank);

	if (!mdev)
		return;

	mutex_lock(&s5p_media_cma_lock);
	if (WARN_ON(mdev->users <= 0))
		goto out;
	if (!--mdev->users)
		free_contig_range(__phys_to_pfn(mdev->paddr),
				  mdev->cma_size >> PAGE_SHIFT);
out:
	mutex_unlock(&s5p_media_cma_lock);
}
EXPORT_SYMBOL(s5p_media_put);

static int __init s5p_media_cma_init(void)
{
	struct s5p_media_device *mdev;
	unsigned long base_pfn, pfn, i;
	struct zone *zone;
	int n;

	for (n = 0; n < nr_media_devs; n++) {
		mdev = &media_devs[n];
		if (!mdev->cma_size)
			continue;

		base_pfn = __phys_to_pfn(mdev->paddr);
		zone = page_zone(pfn_to_page(base_pfn));
		for (pfn = base_pfn; pfn < base_pfn +
				(mdev->cma_size >> PAGE_SHIFT); pfn++)
			if (!pfn_valid(pfn) || page_zone(pfn_to_page(pfn)) != zone)
				break;
		if (pfn < base_pfn + (mdev->cma_size >> PAGE_SHIFT)) {
			pr_err("s5p: %s range 0x%08x is not one zone, kept\n",
				mdev->name, mdev->paddr);
			mdev->cma_size = 0;
			continue;
		}

		for (i = 0; i < mdev->cma_size >> PAGE_SHIFT;
				i += pageblock_nr_pages)
			init_cma_reserved_pageblock(pfn_to_page(base_pfn + i));

		pr_info("s5p: %u KB of %s at 0x%08x lent to the system\n",
			mdev->cma_size >> 10, mdev->name, mdev->paddr);
	}

	return 0;
}
core_initcall(s5p_media_cma_init);
#endif

/* FIXME: temporary implementation to avoid compile error */
int dma_needs_bounce(struct device *dev, dma_addr_t addr, size_t size)
{
	return 0;
}


