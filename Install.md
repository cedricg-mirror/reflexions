# Installation procedure  

Disclaimer :

Reflexions Sandbox should be considered as a highly experimental tool which should *NOT* be installed outside a virtualized guest operating system nor on a critical production environment !  
Because of the very deep tempering of both the windows kernel and userland structures, as well as still beeing in an early development stage, it should be expected that various side effects may occur such as :

- Unable to boot the guest
- Blue screen of death
- System hang

It is therefore highly advised to take snapshot of your guest operating system both *before* install and *after* the first successful boot.

It is also advised to restore your analysis environment between each sample supervision.

Note: Because Reflexions is still in active development, the GUI displayed in this guide is suceptible to change before or after release.


## Non interactive mode (without a kernel debugger)  

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

![Installation with debugger](Screenshots/install_dbg.gif)
