Sample init scripts and service configuration for chitad
==========================================================

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/chitad.service:    systemd service unit configuration
    contrib/init/chitad.openrc:     OpenRC compatible SysV style init script
    contrib/init/chitad.openrcconf: OpenRC conf.d file
    contrib/init/chitad.conf:       Upstart service configuration file
    contrib/init/chitad.init:       CentOS compatible SysV style init script

1. Service User
---------------------------------

All three Linux startup configurations assume the existence of a "chitacore" user
and group.  They must be created before attempting to use these scripts.
The OS X configuration assumes chitad will be set up for the current user.

2. Configuration
---------------------------------

At a bare minimum, chitad requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, chitad will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that chitad and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If chitad is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running chitad without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `contrib/debian/examples/chita.conf`.

3. Paths
---------------------------------

3a) Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              `/usr/bin/chitad`  
Configuration file:  `/etc/chitacore/chita.conf`  
Data directory:      `/var/lib/chitad`  
PID file:            `/var/run/chitad/chitad.pid` (OpenRC and Upstart) or `/var/lib/chitad/chitad.pid` (systemd)  
Lock file:           `/var/lock/subsys/chitad` (CentOS)  

The configuration file, PID directory (if applicable) and data directory
should all be owned by the chitacore user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
chitacore user and group.  Access to chita-cli and other chitad rpc clients
can then be controlled by group membership.

3b) Mac OS X

Binary:              `/usr/local/bin/chitad`  
Configuration file:  `~/Library/Application Support/ChitaCore/chita.conf`  
Data directory:      `~/Library/Application Support/ChitaCore`
Lock file:           `~/Library/Application Support/ChitaCore/.lock`

4. Installing Service Configuration
-----------------------------------

4a) systemd

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start chitad` and to enable for system startup run
`systemctl enable chitad`

4b) OpenRC

Rename chitad.openrc to chitad and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/chitad start` and configure it to run on startup with
`rc-update add chitad`

4c) Upstart (for Debian/Ubuntu based distributions)

Drop chitad.conf in /etc/init.  Test by running `service chitad start`
it will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the start-stop-daemon utility.

4d) CentOS

Copy chitad.init to /etc/init.d/chitad. Test by running `service chitad start`.

Using this script, you can adjust the path and flags to the chitad program by
setting the CHID and FLAGS environment variables in the file
/etc/sysconfig/chitad. You can also use the DAEMONOPTS environment variable here.

4e) Mac OS X

Copy org.chita.chitad.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.chita.chitad.plist`.

This Launch Agent will cause chitad to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run chitad as the current user.
You will need to modify org.chita.chitad.plist if you intend to use it as a
Launch Daemon with a dedicated chitacore user.

5. Auto-respawn
-----------------------------------

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
