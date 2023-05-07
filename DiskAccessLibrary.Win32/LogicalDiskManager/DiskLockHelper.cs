/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System.Collections.Generic;
using DiskAccessLibrary.Win32;

namespace DiskAccessLibrary.LogicalDiskManager.Win32
{
    public class DiskLockHelper
    {
        public static bool LockAllOrNone(List<DynamicDisk> dynamicDisks)
        {
            List<PhysicalDisk> physicalDisks = new List<PhysicalDisk>();
            foreach (DynamicDisk dynamicDisk in dynamicDisks)
            {
                if (dynamicDisk.Disk is PhysicalDisk)
                {
                    physicalDisks.Add((PhysicalDisk)dynamicDisk.Disk);
                }
            }
            return PhysicalDiskHelper.LockAllOrNone(physicalDisks);
        }

        public static void ReleaseLock(List<DynamicDisk> dynamicDisks)
        {
            List<PhysicalDisk> physicalDisks = new List<PhysicalDisk>();
            foreach (DynamicDisk dynamicDisk in dynamicDisks)
            {
                if (dynamicDisk.Disk is PhysicalDisk)
                {
                    ((PhysicalDisk)(dynamicDisk.Disk)).ReleaseLock();
                }
            }
        }
    }
}
