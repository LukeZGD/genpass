## genpass
A tool to generate vfdecrypt key to decrypt iOS filesystems.

### Usage

	genpass -p <platform> -r <ramdisk.dmg> -f <filesystem.dmg>
	genpass -h <hex passphrase> -f <filesystem.dmg>

	platform: s5l8900x (for iphone2g, iphone3g, and ipod1g), s5l8720x (for ipod2g),
	          s5l8920x (for iphone3gs), s5l8922x (for ipod3g), or s5l8930x (for iPhone4, ipad1g, ATV2)
    ramdisk.dmg: a decrypted restore or upgrade ramdisk from the IPSW with the target filesystem
    filesystem.dmg: the encrypted filesystem you're trying to discover the vfdecrypt key for
