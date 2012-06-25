## genpass
A tool to generate vfdecrypt key to decrypt iOS filesystems.

### Usage

	genpass -p <platform> -r <ramdisk.dmg> -f <filesystem.dmg>

---
* `platform`:
	+ `s5l8900x` (for iPhone1,1; iPhone1,2; iPod1,1)
	+ `s5l8720x` (for iPod2,1)
	+ `s5l8920x` (for iPhone2,1)
	+ `s5l8922x` (for iPod3,1)
	+ `s5l8930x` (for iPhone3,1; iPad1,1; iPod4,1;  AppleTV2,1)
* `ramdisk.dmg`: a decrypted restore or update ramdisk from the IPSW with the target filesystem
* `filesystem.dmg`: the encrypted filesystem you're trying to discover the vfdecrypt key for
