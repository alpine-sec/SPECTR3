/*
 * Synchronous I/O file backing store routine
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#define _XOPEN_SOURCE 600

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "scsi.h"
#include "spc.h"
#include "bs_thread.h"

static void cmd_error_sense(struct scsi_cmd *cmd, uint8_t key, uint16_t asc)
{
	scsi_set_result(cmd, SAM_STAT_CHECK_CONDITION);
	sense_data_build(cmd, key, asc);
}

#define set_medium_error(cmd) cmd_error_sense(cmd, MEDIUM_ERROR, ASC_READ_ERROR)

static void bs_rdwr_request(struct scsi_cmd *cmd)
{
	int ret = 0;
	int fd = cmd->dev->fd;
	uint32_t length = 0;
	char *tmpbuf;
	size_t blocksize;
	uint64_t offset = cmd->offset;
	uint32_t tl     = cmd->tl;
	int do_verify = 0;
	int i;
	char *ptr;
	const char *write_buf = NULL;

	/* overwritten on error */
	scsi_set_result(cmd, SAM_STAT_GOOD);

	switch (cmd->scb[0])
	{
	case ORWRITE_16:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			cmd_error_sense(cmd, HARDWARE_ERROR,
					ASC_INTERNAL_TGT_FAILURE);
			break;
		}

		ret = pread64(fd, tmpbuf, length, offset);

		if (ret != length) {
			set_medium_error(cmd);
			free(tmpbuf);
			break;
		}

		ptr = scsi_get_out_buffer(cmd);
		for (i = 0; i < length; i++)
			ptr[i] |= tmpbuf[i];

		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd);
		goto write;
	case COMPARE_AND_WRITE:
		/* Blocks are transferred twice, first the set that
		 * we compare to the existing data, and second the set
		 * to write if the compare was successful.
		 */
		length = scsi_get_out_length(cmd) / 2;
		if (length != cmd->tl) {
			cmd_error_sense(cmd, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_CDB);
			break;
		}

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			cmd_error_sense(cmd, HARDWARE_ERROR,
					ASC_INTERNAL_TGT_FAILURE);
			break;
		}

		ret = pread64(fd, tmpbuf, length, offset);

		if (ret != length) {
			set_medium_error(cmd);
			free(tmpbuf);
			break;
		}

		if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			uint64_t pos = 0;
			char *spos = scsi_get_out_buffer(cmd);
			char *dpos = tmpbuf;

			/*
			 * Data differed, this is assumed to be 'rare'
			 * so use a much more expensive byte-by-byte
			 * comparasion to find out at which offset the
			 * data differs.
			 */
			for (pos = 0; pos < length && *spos++ == *dpos++;
			     pos++)
				;
			free(tmpbuf);
			scsi_set_result(cmd, SAM_STAT_CHECK_CONDITION);
			sense_data_build_with_info(cmd, MISCOMPARE,
				ASC_MISCOMPARE_DURING_VERIFY_OPERATION, pos);
			break;
		}

		if (cmd->scb[1] & 0x10)
			posix_fadvise(fd, offset, length,
				      POSIX_FADV_NOREUSE);

		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd) + length;
		goto write;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		/* TODO */
		length = (cmd->scb[0] == SYNCHRONIZE_CACHE) ? 0 : 0;

		if (cmd->scb[1] & 0x2) {
			cmd_error_sense(cmd, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_CDB);
		} else {
			ret = fdatasync(fd);
			if (ret)
				set_medium_error(cmd);
		}
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		do_verify = 1;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = scsi_get_out_length(cmd);
		write_buf = scsi_get_out_buffer(cmd);
write:
		ret = pwrite64(fd, write_buf, length,
			       offset);
		if (ret == length) {
			struct mode_pg *pg;

			/*
			 * it would be better not to access to pg
			 * directy.
			 */
			pg = find_mode_page(cmd->dev, 0x08, 0);
			if (pg == NULL) {
				cmd_error_sense(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
				break;
			}
			if (((cmd->scb[0] != WRITE_6) && (cmd->scb[1] & 0x8)) ||
			    !(pg->mode_data[0] & 0x04)) {
				ret = fdatasync(fd);
				if (ret)
					set_medium_error(cmd);
			}
		} else
			set_medium_error(cmd);

		if ((cmd->scb[0] != WRITE_6) && (cmd->scb[1] & 0x10))
			posix_fadvise(fd, offset, length,
				      POSIX_FADV_NOREUSE);
		if (do_verify)
			goto verify;
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		/* WRITE_SAME used to punch hole in file */
		if (cmd->scb[1] & 0x08) {
			ret = unmap_file_region(fd, offset, tl);
			if (ret != 0) {
				eprintf("Failed to punch hole for WRITE_SAME"
					" command\n");
				cmd_error_sense(cmd, HARDWARE_ERROR,
						ASC_INTERNAL_TGT_FAILURE);
				break;
			}
			break;
		}
		while (tl > 0) {
			blocksize = 1 << cmd->dev->blk_shift;
			tmpbuf = scsi_get_out_buffer(cmd);

			switch(cmd->scb[1] & 0x06) {
			case 0x02: /* PBDATA==0 LBDATA==1 */
				put_unaligned_be32(offset, tmpbuf);
				break;
			case 0x04: /* PBDATA==1 LBDATA==0 */
				/* physical sector format */
				put_unaligned_be64(offset, tmpbuf);
				break;
			}

			ret = pwrite64(fd, tmpbuf, blocksize, offset);
			if (ret != blocksize)
				set_medium_error(cmd);

			offset += blocksize;
			tl     -= blocksize;
		}
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = scsi_get_in_length(cmd);
		ret = pread64(fd, scsi_get_in_buffer(cmd), length,
			      offset);

		if (ret != length)
			set_medium_error(cmd);

		if ((cmd->scb[0] != READ_6) && (cmd->scb[1] & 0x10))
			posix_fadvise(fd, offset, length,
				      POSIX_FADV_NOREUSE);

		break;
	case PRE_FETCH_10:
	case PRE_FETCH_16:
		ret = posix_fadvise(fd, offset, cmd->tl,
				POSIX_FADV_WILLNEED);

		if (ret != 0)
			set_medium_error(cmd);
		break;
	case VERIFY_10:
	case VERIFY_12:
	case VERIFY_16:
verify:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			cmd_error_sense(cmd, HARDWARE_ERROR,
					ASC_INTERNAL_TGT_FAILURE);
			break;
		}

		ret = pread64(fd, tmpbuf, length, offset);

		if (ret != length)
			set_medium_error(cmd);
		else if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			cmd_error_sense(cmd, MISCOMPARE,
					ASC_MISCOMPARE_DURING_VERIFY_OPERATION);
		}

		if (cmd->scb[1] & 0x10)
			posix_fadvise(fd, offset, length,
				      POSIX_FADV_NOREUSE);

		free(tmpbuf);
		break;
	case UNMAP:
		if (!cmd->dev->attrs.thinprovisioning) {
			cmd_error_sense(cmd, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_CDB);
			break;
		}

		length = scsi_get_out_length(cmd);
		tmpbuf = scsi_get_out_buffer(cmd);

		if (length < 8)
			break;

		length -= 8;
		tmpbuf += 8;

		while (length >= 16) {
			offset = get_unaligned_be64(&tmpbuf[0]);
			offset = offset << cmd->dev->blk_shift;

			tl = get_unaligned_be32(&tmpbuf[8]);
			tl = tl << cmd->dev->blk_shift;

			if (offset + tl > cmd->dev->size) {
				eprintf("UNMAP beyond EOF\n");
				cmd_error_sense(cmd, ILLEGAL_REQUEST,
						ASC_LBA_OUT_OF_RANGE);
				break;
			}

			if (tl > 0) {
				if (unmap_file_region(fd, offset, tl) != 0) {
					eprintf("Failed to punch hole for"
						" UNMAP at offset:%" PRIu64
						" length:%d\n",
						offset, tl);
					cmd_error_sense(cmd, HARDWARE_ERROR,
						ASC_INTERNAL_TGT_FAILURE);
					break;
				}
			}

			length -= 16;
			tmpbuf += 16;
		}
		break;
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	if (scsi_get_result(cmd) != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, offset);
	}
}

static int bs_rdwr_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	uint32_t blksize = 0;

	*fd = backed_file_open(path, O_RDWR|O_LARGEFILE|lu->bsoflags, size,
				&blksize);
	/* If we get access denied, try opening the file in readonly mode */
	if (*fd == -1 && (errno == EACCES || errno == EROFS)) {
		*fd = backed_file_open(path, O_RDONLY|O_LARGEFILE|lu->bsoflags,
				       size, &blksize);
		lu->attrs.readonly = 1;
	}
	if (*fd < 0)
		return *fd;

	if (!lu->attrs.no_auto_lbppbe)
		update_lbppbe(lu, blksize);

	return 0;
}

static void bs_rdwr_close(struct scsi_lu *lu)
{
	close(lu->fd);
}

static tgtadm_err bs_rdwr_init(struct scsi_lu *lu, char *bsopts)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	return bs_thread_open(info, bs_rdwr_request, nr_iothreads);
}

static void bs_rdwr_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);

	bs_thread_close(info);
}

static struct backingstore_template rdwr_bst = {
	.bs_name		= "rdwr",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_rdwr_open,
	.bs_close		= bs_rdwr_close,
	.bs_init		= bs_rdwr_init,
	.bs_exit		= bs_rdwr_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT,
};

static struct backingstore_template mmc_bst = {
	.bs_name		= "mmc",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_rdwr_open,
	.bs_close		= bs_rdwr_close,
	.bs_init		= bs_rdwr_init,
	.bs_exit		= bs_rdwr_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT,
};

static struct backingstore_template smc_bst = {
	.bs_name		= "smc",
	.bs_datasize		= sizeof(struct bs_thread_info),
	.bs_open		= bs_rdwr_open,
	.bs_close		= bs_rdwr_close,
	.bs_init		= bs_rdwr_init,
	.bs_exit		= bs_rdwr_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT,
};

__attribute__((constructor)) static void bs_rdwr_constructor(void)
{
	unsigned char sbc_opcodes[] = {
		ALLOW_MEDIUM_REMOVAL,
		COMPARE_AND_WRITE,
		FORMAT_UNIT,
		INQUIRY,
		MAINT_PROTOCOL_IN,
		MODE_SELECT,
		MODE_SELECT_10,
		MODE_SENSE,
		MODE_SENSE_10,
		ORWRITE_16,
		PERSISTENT_RESERVE_IN,
		PERSISTENT_RESERVE_OUT,
		PRE_FETCH_10,
		PRE_FETCH_16,
		READ_10,
		READ_12,
		READ_16,
		READ_6,
		READ_CAPACITY,
		RELEASE,
		REPORT_LUNS,
		REQUEST_SENSE,
		RESERVE,
		SEND_DIAGNOSTIC,
		SERVICE_ACTION_IN,
		START_STOP,
		SYNCHRONIZE_CACHE,
		SYNCHRONIZE_CACHE_16,
		TEST_UNIT_READY,
		UNMAP,
		VERIFY_10,
		VERIFY_12,
		VERIFY_16,
		WRITE_10,
		WRITE_12,
		WRITE_16,
		WRITE_6,
		WRITE_SAME,
		WRITE_SAME_16,
		WRITE_VERIFY,
		WRITE_VERIFY_12,
		WRITE_VERIFY_16
	};
	bs_create_opcode_map(&rdwr_bst, sbc_opcodes, ARRAY_SIZE(sbc_opcodes));
	register_backingstore_template(&rdwr_bst);

	unsigned char mmc_opcodes[] = {
		ALLOW_MEDIUM_REMOVAL,
		CLOSE_TRACK,
		GET_CONFIGURATION,
		GET_PERFORMACE,
		INQUIRY,
		MODE_SELECT,
		MODE_SELECT_10,
		MODE_SENSE,
		MODE_SENSE_10,
		PERSISTENT_RESERVE_IN,
		PERSISTENT_RESERVE_OUT,
		READ_10,
		READ_12,
		READ_BUFFER_CAP,
		READ_CAPACITY,
		READ_DISK_INFO,
		READ_DVD_STRUCTURE,
		READ_TOC,
		READ_TRACK_INFO,
		RELEASE,
		REPORT_LUNS,
		REQUEST_SENSE,
		RESERVE,
		SET_CD_SPEED,
		SET_STREAMING,
		START_STOP,
		SYNCHRONIZE_CACHE,
		TEST_UNIT_READY,
		VERIFY_10,
		WRITE_10,
		WRITE_12,
		WRITE_VERIFY,
	};
	bs_create_opcode_map(&mmc_bst, mmc_opcodes, ARRAY_SIZE(mmc_opcodes));
	register_backingstore_template(&mmc_bst);

	unsigned char smc_opcodes[] = {
		INITIALIZE_ELEMENT_STATUS,
		INITIALIZE_ELEMENT_STATUS_WITH_RANGE,
		INQUIRY,
		MAINT_PROTOCOL_IN,
		MODE_SELECT,
		MODE_SELECT_10,
		MODE_SENSE,
		MODE_SENSE_10,
		MOVE_MEDIUM,
		PERSISTENT_RESERVE_IN,
		PERSISTENT_RESERVE_OUT,
		REQUEST_SENSE,
		TEST_UNIT_READY,
		READ_ELEMENT_STATUS,
		RELEASE,
		REPORT_LUNS,
		RESERVE,
	};
	bs_create_opcode_map(&smc_bst, smc_opcodes, ARRAY_SIZE(smc_opcodes));
	register_backingstore_template(&smc_bst);
}
