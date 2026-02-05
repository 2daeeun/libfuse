# # /mnt/nvme0n1p4/ (200MB)
# sudo umount /mnt/nvme0n1p4/
# sudo dd if=/dev/zero of=/dev/nvme0n1p4 bs=4M status=progress && sync
# sudo mkfs.ext4 /dev/nvme0n1p4
# sudo mount /dev/nvme0n1p4 /mnt/nvme0n1p4/

# # /mnt/nvme0n1p5/ (200MB)
# sudo umount /mnt/nvme0n1p5/
# sudo dd if=/dev/zero of=/dev/nvme0n1p5 bs=4M status=progress && sync
# sudo mkfs.ext4 /dev/nvme0n1p5
# sudo mount /dev/nvme0n1p5 /mnt/nvme0n1p5/

# /mnt/nvme0n1p6/ (16GB)
# sudo umount /mnt/nvme0n1p6/
# sudo dd if=/dev/zero of=/dev/nvme0n1p6 bs=4M status=progress && sync
# sudo mkfs.ext4 /dev/nvme0n1p6
# sudo mount /dev/nvme0n1p6 /mnt/nvme0n1p6/

# # /mnt/nvme0n1p7/ (16GB)
# sudo umount /mnt/nvme0n1p7/
# sudo dd if=/dev/zero of=/dev/nvme0n1p7 bs=4M status=progress && sync
# sudo mkfs.ext4 /dev/nvme0n1p7
# sudo mount /dev/nvme0n1p7 /mnt/nvme0n1p7/

# # /mnt/nvme0n1p8/ (80GB)
sudo rm -r /mnt/fuse/
sudo mkdir /mnt/fuse/
sudo umount /mnt/nvme0n1p8/
sudo dd if=/dev/zero of=/dev/nvme0n1p8 bs=4M status=progress && sync
sudo mkfs.ext4 /dev/nvme0n1p8
sudo mount /dev/nvme0n1p8 /mnt/nvme0n1p8/
