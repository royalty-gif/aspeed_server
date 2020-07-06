#!/bin/sh

FW_PATH="/dev/shm"
FW_BOOT="mtdblkboot"
FW_KERNEL="mtdblkkernel"
FW_ROOTFS="mtdblkrootfs"
FW_PATCH="mtdblkrootfsp"
FW_LOGO="mtdblklogo"

total_fw_size()
{
	fsize='0'
	if [ -f "$FW_PATH/$FW_BOOT" ]; then
		set -- `ls -l $FW_PATH/$FW_BOOT`
		#echo "$FW_BOOT size $5 B"
		fsize=`expr $fsize + $5`
	fi
	if [ -f "$FW_PATH/$FW_KERNEL" ]; then
		set -- `ls -l $FW_PATH/$FW_KERNEL`
		#echo "$FW_KERNEL size $5 B"
		fsize=`expr $fsize + $5`
	fi
	if [ -f "$FW_PATH/$FW_ROOTFS" ]; then
		set -- `ls -l $FW_PATH/$FW_ROOTFS`
		#echo "$FW_ROOTFS size $5 B"
		fsize=`expr $fsize + $5`
	fi
	if [ -f "$FW_PATH/$FW_PATCH" ]; then
		set -- `ls -l $FW_PATH/$FW_PATCH`
		#echo "$FW_PATCH size $5 B"
		fsize=`expr $fsize + $5`
	fi
	if [ -f "$FW_PATH/$FW_LOGO" ]; then
		set -- `ls -l $FW_PATH/$FW_LOGO`
		#echo "$FW_LOGO size $5 B"
		fsize=`expr $fsize + $5`
	fi
	echo "$fsize"
}

async_update()
{
	# untar fw
	if ! tar zxvf fw.tar.gz ; then
		echo "Un-pack firmware failed!"
		return
	fi
	rm -f fw.tar.gz
	if ! [ -f "./flash.sh" ]; then
		echo "Not a valid fw"
		return
	fi
	_fw_size=`total_fw_size`
	chmod a+x ./flash.sh
	if ! ./flash.sh ; then
		# don't reboot
		echo "./flash.sh failed!"
		return
	fi
	rm -f flash.sh
	sleep 10
	reboot
}



cd /dev/shm
# Remove all fw files if exists
rm -f mtdblk*
rm -f flash.sh

# Bruce160714. RctBug#2016071300. In case of watchdog false alert, we disable watchdog when updating FW.
if [ -d /sys/devices/platform/watchdog ]; then
	echo no > /sys/devices/platform/watchdog/enable
fi

async_update &
exit 0

