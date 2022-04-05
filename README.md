# usbmuxd_debug

## start usbmuxd capture

```SHELL
sudo ./dump_usbmuxd.sh /path/to/file.pcap

```

## load plugin

put the `bplist.lua` `usbmuxd.lua` in `~/.config/wireshark/plugins/`

## Check in wireshark

1. open wireshark select lo0
2. filter with `udp.port==9876`
3. import `tlskeys.log` to decrypt tls
