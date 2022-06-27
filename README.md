# mtdmon
Script that scans and reports new Bad Blocks and ECC errors on mtd/nand devices on Asuswrt-merlin based routers.
It can optionally email and/or send an sms text message (via email) when new errors are detected and also a daily or weekly report.
Mtdmon will install the application, mtd_check. This application does the actual reading of information and error statistics of mtd devices.

**Note: mtdmon (and mtd_check) only works with the mtd character devices (i.e. /dev/mtd0, /dev/mtd9, etc.) _not_ the block devices (/dev/mtdblock0, /dev/mtdblock9, etc.). It also will not report any information for ubi formatted mtd partitions.**


## Installation

Using your preferred SSH client/terminal, copy and paste the following command, then press Enter:

/usr/sbin/curl --retry 3 "https://raw.githubusercontent.com/JGrana01/mtdmon/main/mtdmon.sh" -o "/jffs/scripts/mtdmon" && chmod 0755 /jffs/scripts/mtdmon && /jffs/scripts/mtdmon install

mtdmon will make sure you have Entware installed and that your kernel is an armv7l or aarch64 version. If not, it will not install the appropriate binary (in /opt/bin) and exit.
The mtdmon script will stay in /jffs/scripts (it's small) and can be used to re-install/update the mtdmon addon and mtd_check binary.

## Usage

mtdmon runs once a day (after midnight) to check the routers mtd devices for new bad blocks and ECC errors. If detected, mtdmon can send an email and/or txt message to alert the user that a new bad block or ECC error was detected. Mtdmon will always display the latest results when started by the command line.

mtdmon can also be run from the command line. This is done to changes email settings, the list of mtd devices (partitions) to scan, run a scan and also view the various reports.

$ mtdmon

The -i option just displays the Flash type, Block size, page size and OOB size along with the total number of bytes and blocks on the mtd partition.
The -b option only reports the number of bad blocks on the partition. This can be useful for sh/bash scripts to monitor mtd partitions for potential growing bad blocks.

**Note: mtd_check only works with the mtd character devices (i.e. /dev/mtd0, /dev/mtd9, etc.) _not_ the block devices (/dev/mtdblock0, /dev/mtdblock9, etc.). It also will not report any information for ubi formatted mtd partitions.**

One way  to see the available mtd partitions is to cat /proc/mtd:
```
$ cat /proc/mtd
dev:    size   erasesize  name
mtd0: 051c0000 00020000 "rootfs"
mtd1: 051c0000 00020000 "rootfs_update"
mtd2: 00800000 00020000 "data"
mtd3: 00100000 00020000 "nvram"
mtd4: 05700000 00020000 "image_update"
mtd5: 05700000 00020000 "image"
mtd6: 00520000 00020000 "bootfs"
mtd7: 00520000 00020000 "bootfs_update"
mtd8: 00100000 00020000 "misc3"
mtd9: 03f00000 00020000 "misc2"
mtd10: 00800000 00020000 "misc1"
mtd11: 04d23000 0001f000 "rootfs_ubifs"
```
Note that mtd11 (on an AX88U) is a ubi formatted partition and is not supported

Without the -i or -b options, mtd_check will walk all the blocks showing their state:

- **B**&nbsp; &nbsp; &nbsp;Bad block
- **\.**&nbsp; &nbsp; &nbsp;Empty
- **\-**&nbsp; &nbsp; &nbsp;Partially filled
- **\=**&nbsp; &nbsp; &nbsp;Full
- **s**&nbsp; &nbsp; &nbsp;partial with summry node
- **S**&nbsp; &nbsp; &nbsp;has a JFFS2 summary node

Something like this:

```
$ mtd_check /dev/mtd0
Flash type of /dev/mtd0 is 4 (MTD_NANDFLASH)
Flash flags are 400
Block size 131072, page size 2048, OOB size 64
99614720 bytes, 760 blocks
B Bad block; . Empty; - Partially filled; = Full; S has a JFFS2 summary node
-----------===========================------------==============================
=======B========================================================================
================================================================================
================================================================================
=========================================================================B======
================================================================================
================================================================================
=============================================================B==================
=========================================-===========---------------------------
----------------------------------------
Summary blocks: 0
Summary /dev/mtd0:
Total Blocks: 760  Total Size: 1520.0 KB
Empty Blocks: 0, Full Blocks: 666, Partially Full: 91, Bad Blocks: 3
```
## Uninstall

To remove mtd_check, remove the installer and binary:
```
$ rm /jffs/scripts/mtd_check_install
$ rm /opt/bin/mtd_check
```

