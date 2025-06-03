# Installation procedure  

## Non interactive mode  

- Boot a Windows 7 x64 / 8.1 x64 / 10 x64 Guest
- Take a snapshot
- Launch the installer
- Reboot and press F8 on the Reflexions boot entry
- Select Disable Driver Signature Enforcment
- Take a snapshot :)

![Installation No debugger](Screenshots/install_no_debugger.gif)

## Interactive mode (kernel debugger)  

- Setup your kernel debugging environment (I highly recommend [VirtualKD-Redux](https://github.com/4d61726b/VirtualKD-Redux/blob/master/VirtualKD-Redux/Docs/Tutorial.md))
- Boot a Windows 7 x64 / 8.1 x64 / 10 x64 Guest connected to your kernel debugger
- Take a snapshot
- Launch the installer
- Reboot and press F8 on your kernel debug boot entry
- Select Disable Driver Signature Enforcment
- Take a snapshot :)
