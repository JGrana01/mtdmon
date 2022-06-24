#!/bin/sh
#################################################
##                                             ##
##                mtdmon                       ## 
##        for AsusWRT-Merlin routers           ##
##                                             ##
##            Watch for badblocks on           ##
##          mtd devices (/dev/mtdX)            ##
##    scripts heavily uses script functions    ##
##    by Jack Yaz and others                   ##
##    https://github.com/JGrana01/mtdmon       ##
##                                             ##
#################################################

########         Shellcheck directives     ######
# shellcheck disable=SC1091
# shellcheck disable=SC2009
# shellcheck disable=SC2016
# shellcheck disable=SC2018
# shellcheck disable=SC2019
# shellcheck disable=SC2059
# shellcheck disable=SC2086
# shellcheck disable=SC2154
# shellcheck disable=SC2155

# shellcheck disable=SC2181
#################################################

### Start of script variables ###
readonly SCRIPT_NAME="mtdmon"
readonly SCRIPT_VERSION="v0.6.1"
SCRIPT_BRANCH="main"
MTDAPP_BRANCH="main"
SCRIPT_REPO="https://raw.githubusercontent.com/JGrana01/mtdmon/$SCRIPT_BRANCH"
MTDAPP_REPO="https://raw.githubusercontent.com/JGrana01/mtd_check/$MTDAPP_BRANCH"
readonly SCRIPT_DIR="/jffs/addons/$SCRIPT_NAME.d"

# No web page support at this time but leave for now
readonly SCRIPT_WEBPAGE_DIR="$(readlink /www/user)"
readonly SCRIPT_WEB_DIR="$SCRIPT_WEBPAGE_DIR/$SCRIPT_NAME"
readonly SHARED_DIR="/jffs/addons/shared-jy"

# the above are not used - saved for potential future usage


readonly MTD_CHECK_COMMAND="/opt/bin/mtd_check"
#readonly MTD_CHECK_COMMAND="/jffs/scripts/sandbox/mtdmon/mtd_check" # for testing
readonly MTDAPP_DIR="/opt/bin"

MTDEVPART="$SCRIPT_DIR/mtddevs"
VALIDMTDS="$SCRIPT_DIR/validmtds"
MTDMONLIST="$SCRIPT_DIR/mtdmonlist"
MTDLOG="$SCRIPT_DIR/mtdlog"
MTDREPORT="$SCRIPT_DIR/mtdreport"
MTDERRORS="$SCRIPT_DIR/mtderrors"
MTDERRLOG="$SCRIPT_DIR/mtderrorlog"
MTDWEEKLY="$SCRIPT_DIR/mtdweekly"
LASTRESULTS="$SCRIPT_DIR/lastresult"
PREVIOUSERRORS="$SCRIPT_DIR/previouserrors"
debug=0


readonly SHARED_REPO="https://raw.githubusercontent.com/jackyaz/shared-jy/master"
readonly SHARED_WEB_DIR="$SCRIPT_WEBPAGE_DIR/shared-jy"
[ -z "$(nvram get odmpid)" ] && ROUTER_MODEL=$(nvram get productid) || ROUTER_MODEL=$(nvram get odmpid)
ISHND=$(nvram get rc_support | grep -cw "bcmhnd")

### End of script variables ###

### Start of output format variables ###
readonly CRIT="\\e[41m"
readonly ERR="\\e[31m"
readonly WARN="\\e[33m"
readonly PASS="\\e[32m"
readonly BOLD="\\e[1m"
readonly SETTING="${BOLD}\\e[36m"
readonly CLEARFORMAT="\\e[0m"
### End of output format variables ###

# $1 = print to syslog, $2 = message to print, $3 = log level
Print_Output(){
	if [ "$1" = "true" ]; then
		logger -t "$SCRIPT_NAME" "$2"
	fi
	printf "${BOLD}${3}%s${CLEARFORMAT}\\n\\n" "$2"
}

# print out a message if debug is enabled
# $1 = print to syslog, $2 = message to print
Debug_Output(){
	if [ $debug = 1 ]; then
		if [ "$1" = "true" ]; then
			logger -t "$SCRIPT_NAME" "$2"
		fi
		printf "${BOLD}${3}%s${CLEARFORMAT}\\n\\n" "$2"
	fi
}

### Check firmware version contains the "am_addons" feature flag ###
Firmware_Version_Check(){
	if nvram get rc_support | grep -qF "am_addons"; then
		return 0
	else
		return 1
	fi
}

### Create "lock" file to ensure script only allows 1 concurrent process for certain actions ###
### Code for these functions inspired by https://github.com/Adamm00 - credit to @Adamm ###
Check_Lock(){
	if [ -f "/tmp/$SCRIPT_NAME.lock" ]; then
		ageoflock=$(($(date +%s) - $(date +%s -r /tmp/$SCRIPT_NAME.lock)))
		if [ "$ageoflock" -gt 600 ]; then
			Print_Output true "Stale lock file found (>600 seconds old) - purging lock" "$ERR"
			kill "$(sed -n '1p' /tmp/$SCRIPT_NAME.lock)" >/dev/null 2>&1
			Clear_Lock
			echo "$$" > "/tmp/$SCRIPT_NAME.lock"
			return 0
		else
			Print_Output true "Lock file found (age: $ageoflock seconds)" "$ERR"
			if [ -z "$1" ]; then
				exit 1
			else
				if [ "$1" = "webui" ]; then
					echo 'var mtdmon = "LOCKED";' > /tmp/detect_mtdmon.js
					exit 1
				fi
				return 1
			fi
		fi
	else
		echo "$$" > "/tmp/$SCRIPT_NAME.lock"
		return 0
	fi
}

Clear_Lock(){
	rm -f "/tmp/$SCRIPT_NAME.lock" 2>/dev/null
	return 0
}
############################################################################

### Create "settings" in the custom_settings file, used by the WebUI for version information and script updates ###
### local is the version of the script installed, server is the version on Github ###
Set_Version_Custom_Settings(){
	SETTINGSFILE="/jffs/addons/custom_settings.txt"
	case "$1" in
		local)
			if [ -f "$SETTINGSFILE" ]; then
				if [ "$(grep -c "mtdmon_version_local" $SETTINGSFILE)" -gt 0 ]; then
					if [ "$2" != "$(grep "mtdmon_version_local" /jffs/addons/custom_settings.txt | cut -f2 -d' ')" ]; then
						sed -i "s/mtdmon_version_local.*/mtdmon_version_local $2/" "$SETTINGSFILE"
					fi
				else
					echo "mtdmon_version_local $2" >> "$SETTINGSFILE"
				fi
			else
				echo "mtdmon_version_local $2" >> "$SETTINGSFILE"
			fi
		;;
		server)
			if [ -f "$SETTINGSFILE" ]; then
				if [ "$(grep -c "mtdmon_version_server" $SETTINGSFILE)" -gt 0 ]; then
					if [ "$2" != "$(grep "mtdmon_version_server" /jffs/addons/custom_settings.txt | cut -f2 -d' ')" ]; then
						sed -i "s/mtdmon_version_server.*/mtdmon_version_server $2/" "$SETTINGSFILE"
					fi
				else
					echo "mtdmon_version_server $2" >> "$SETTINGSFILE"
				fi
			else
				echo "mtdmon_version_server $2" >> "$SETTINGSFILE"
			fi
		;;
	esac
}

### Checks for changes to Github version of script and returns reason for change (version or md5/minor), local version and server version ###
Update_Check(){
	doupdate="false"
	localver=$(grep "SCRIPT_VERSION=" "/jffs/scripts/$SCRIPT_NAME" | grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})')
	/usr/sbin/curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" | grep -qF "de-vnull" || { Print_Output true "404 error detected - stopping update" "$ERR"; return 1; }
	serverver=$(/usr/sbin/curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" | grep "SCRIPT_VERSION=" | grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})')
	if [ "$localver" != "$serverver" ]; then
		doupdate="version"
		Set_Version_Custom_Settings server "$serverver"
	else
		localmd5="$(md5sum "/jffs/scripts/$SCRIPT_NAME" | awk '{print $1}')"
		remotemd5="$(curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" | md5sum | awk '{print $1}')"
		if [ "$localmd5" != "$remotemd5" ]; then
			doupdate="md5"
			Set_Version_Custom_Settings server "$serverver-hotfix"
		fi
	fi
	echo "$doupdate,$localver,$serverver"
}

### Updates the script from Github including any secondary files ###
### Accepts arguments of:
### force - download from server even if no change detected
### unattended - don't return user to script CLI menu
Update_Version(){
	if [ -z "$1" ]; then
		updatecheckresult="$(Update_Check)"
		isupdate="$(echo "$updatecheckresult" | cut -f1 -d',')"
		localver="$(echo "$updatecheckresult" | cut -f2 -d',')"
		serverver="$(echo "$updatecheckresult" | cut -f3 -d',')"
		
		if [ "$isupdate" = "version" ]; then
			Print_Output true "New version of $SCRIPT_NAME available - $serverver" "$PASS"
		elif [ "$isupdate" = "md5" ]; then
			Print_Output true "MD5 hash of $SCRIPT_NAME does not match - hotfix available - $serverver" "$PASS"
		fi

		if [ "$isupdate" != "false" ]; then
			printf "\\n${BOLD}Do you want to continue with the update? (y/n)${CLEARFORMAT}  "
			read -r confirm
			case "$confirm" in
				y|Y)
					printf "\\n"
					Update_File mtdmon.conf
					Update_File mtd_check
					/usr/sbin/curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" -o "/jffs/scripts/$SCRIPT_NAME" && Print_Output true "$SCRIPT_NAME successfully updated"
					chmod 0755 "/jffs/scripts/$SCRIPT_NAME"
					Set_Version_Custom_Settings local "$serverver"
					Set_Version_Custom_Settings server "$serverver"
					Clear_Lock
					PressEnter
					exec "$0"
					exit 0
				;;
				*)
					printf "\\n"
					Clear_Lock
					return 1
				;;
			esac
		else
			Print_Output true "No updates available - latest is $localver" "$WARN"
			Clear_Lock
		fi
	fi
	
	if [ "$1" = "force" ]; then
		serverver=$(/usr/sbin/curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" | grep "SCRIPT_VERSION=" | grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})')
		Print_Output true "Downloading latest version ($serverver) of $SCRIPT_NAME" "$PASS"
		Update_File mtdmon.conf
		Update_File mtd_check
		/usr/sbin/curl -fsL --retry 3 "$SCRIPT_REPO/$SCRIPT_NAME.sh" -o "/jffs/scripts/$SCRIPT_NAME" && Print_Output true "$SCRIPT_NAME successfully updated"
		chmod 0755 "/jffs/scripts/$SCRIPT_NAME"
		Set_Version_Custom_Settings local "$serverver"
		Set_Version_Custom_Settings server "$serverver"
		Clear_Lock
		if [ -z "$2" ]; then
			PressEnter
			exec "$0"
		elif [ "$2" = "unattended" ]; then
			exec "$0" postupdate
		fi
		exit 0
	fi
}

Validate_Number(){
	if [ "$1" -eq "$1" ] 2>/dev/null; then
		return 0
	else
		return 1
	fi
}

Validate_MtdDev(){
        if echo "$1" | /bin/grep -oq '/dev/mtd[0-9]'  ; then
                return 0

        elif echo "$1" | /bin/grep -oq '/dev/mtd1[0-9]'  ; then
                return 0
        else
                return 1
        fi
}

### Perform relevant actions for secondary files when being updated ###
Update_File(){
	if [ "$1" = "mtd_check" ]; then ### mtd_check application
		tmpfile="/tmp/$1"
		Download_File "$MTDAPP_REPO/$1" "$tmpfile"
		if ! diff -q "$tmpfile" "$MTDAPP_DIR/$1" >/dev/null 2>&1; then
			Download_File "$MTDAPP_REPO/$1" "$MTDAPP_DIR/$1"
			chmod 0755 "$MTDAPP_DIR/$1"
			Print_Output true "New version of $1 downloaded" "$PASS"
		fi
		rm -f "$tmpfile"
	elif [ "$1" = "mtdmon" ]; then ### mtdmon script
		tmpfile="/tmp/$1"
		Download_File "$SCRIPT_REPO/$1" "$tmpfile"
		if ! diff -q "$tmpfile" "$SCRIPT_DIR/$1" >/dev/null 2>&1; then
			Download_File "$SCRIPT_REPO/$1" "$SCRIPT_DIR/$1"
			chmod 0755 "$SCRIPT_DIR/$1"
			Print_Output true "New version of $1 downloaded" "$PASS"
		fi
		rm -f "$tmpfile"
	elif [ "$1" = "mtdmon.conf" ]; then ### mtdmon config file
                tmpfile="/tmp/$1"
                Download_File "$SCRIPT_REPO/$1" "$tmpfile"
                if [ ! -f "$SCRIPT_STORAGE_DIR/$1" ]; then
                        Download_File "$SCRIPT_REPO/$1" "$SCRIPT_STORAGE_DIR/$1.default"
                        Download_File "$SCRIPT_REPO/$1" "$SCRIPT_STORAGE_DIR/$1"
                        Print_Output true "$SCRIPT_STORAGE_DIR/$1 does not exist, downloading now." "$PASS"
                elif [ -f "$SCRIPT_STORAGE_DIR/$1.default" ]; then
                        if ! diff -q "$tmpfile" "$SCRIPT_STORAGE_DIR/$1.default" >/dev/null 2>&1; then
                                Download_File "$SCRIPT_REPO/$1" "$SCRIPT_STORAGE_DIR/$1.default"
                                Print_Output true "New default version of $1 downloaded to $SCRIPT_STORAGE_DIR/$1.default, please compare against your $SCRIPT_STORAGE_DIR/$1"
                        fi
                else
                        Download_File "$SCRIPT_REPO/$1" "$SCRIPT_STORAGE_DIR/$1.default"
                        Print_Output true "$SCRIPT_STORAGE_DIR/$1.default does not exist, downloading now. Please compare against your $SCRIPT_STORAGE_DIR/$1" "$PASS"
                fi
		rm -f "$tmpfile"
	else
		return 1
	fi
}

### Create directories in filesystem if they do not exist ###
Create_Dirs(){
	if [ ! -d "$SCRIPT_DIR" ]; then
		mkdir -p "$SCRIPT_DIR"
	fi
	
	if [ ! -d "$SCRIPT_STORAGE_DIR" ]; then
		mkdir -p "$SCRIPT_STORAGE_DIR"
	fi
	
	if [ ! -d "$CSV_OUTPUT_DIR" ]; then ## possibly future feature
		mkdir -p "$CSV_OUTPUT_DIR"
	fi
	
	
}


Conf_Exists(){
	if [ ! -f "$SCRIPT_STORAGE_DIR/mtdmon.conf" ]; then
		Update_File mtdmon.conf
	fi
	
	if [ -f "$SCRIPT_CONF" ]; then
		dos2unix "$SCRIPT_CONF"
		chmod 0644 "$SCRIPT_CONF"
		sed -i -e 's/"//g' "$SCRIPT_CONF"
		if ! grep -q "STORAGELOCATION" "$SCRIPT_CONF"; then
			echo "STORAGELOCATION=jffs" >> "$SCRIPT_CONF"
		fi
		if ! grep -q "OUTPUTTIMEMODE" "$SCRIPT_CONF"; then
			echo "OUTPUTTIMEMODE=unix" >> "$SCRIPT_CONF"
		fi
		return 0
	else
		{ echo "DAILYEMAIL=none"; echo "ERROREMAIL=yes";  echo "EMAILTYPE=text"; echo "SENDSMS=no";  echo "TO_SMS=none"; echo "STORAGELOCATION=jffs"; echo "OUTPUTTIMEMODE=unix"; } > "$SCRIPT_CONF"
		return 1
	fi
}

### Add script hook to service-event and pass service_event argument and all other arguments passed to the service call ###
Auto_ServiceEvent(){
	case $1 in
		create)
			if [ -f /jffs/scripts/service-event ]; then
				STARTUPLINECOUNT=$(grep -c '# '"$SCRIPT_NAME" /jffs/scripts/service-event)
				STARTUPLINECOUNTEX=$(grep -cx "/jffs/scripts/$SCRIPT_NAME service_event"' "$@" & # '"$SCRIPT_NAME" /jffs/scripts/service-event)
				
				if [ "$STARTUPLINECOUNT" -gt 1 ] || { [ "$STARTUPLINECOUNTEX" -eq 0 ] && [ "$STARTUPLINECOUNT" -gt 0 ]; }; then
					sed -i -e '/# '"$SCRIPT_NAME"'/d' /jffs/scripts/service-event
				fi
				
				if [ "$STARTUPLINECOUNTEX" -eq 0 ]; then
					echo "/jffs/scripts/$SCRIPT_NAME service_event"' "$@" & # '"$SCRIPT_NAME" >> /jffs/scripts/service-event
				fi
			else
				echo "#!/bin/sh" > /jffs/scripts/service-event
				echo "" >> /jffs/scripts/service-event
				echo "/jffs/scripts/$SCRIPT_NAME service_event"' "$@" & # '"$SCRIPT_NAME" >> /jffs/scripts/service-event
				chmod 0755 /jffs/scripts/service-event
			fi
		;;
		delete)
			if [ -f /jffs/scripts/service-event ]; then
				STARTUPLINECOUNT=$(grep -c '# '"$SCRIPT_NAME" /jffs/scripts/service-event)
				
				if [ "$STARTUPLINECOUNT" -gt 0 ]; then
					sed -i -e '/# '"$SCRIPT_NAME"'/d' /jffs/scripts/service-event
				fi
			fi
		;;
	esac
}

### Add script hook to post-mount and pass startup argument and all other arguments passed with the partition mount ###
Auto_Startup(){
	case $1 in
		create)
			if [ -f /jffs/scripts/post-mount ]; then
				STARTUPLINECOUNT=$(grep -c '# '"$SCRIPT_NAME" /jffs/scripts/post-mount)
				STARTUPLINECOUNTEX=$(grep -cx "/jffs/scripts/$SCRIPT_NAME startup"' "$@" & # '"$SCRIPT_NAME" /jffs/scripts/post-mount)
				
				if [ "$STARTUPLINECOUNT" -gt 1 ] || { [ "$STARTUPLINECOUNTEX" -eq 0 ] && [ "$STARTUPLINECOUNT" -gt 0 ]; }; then
					sed -i -e '/# '"$SCRIPT_NAME"'/d' /jffs/scripts/post-mount
				fi
				
				if [ "$STARTUPLINECOUNTEX" -eq 0 ]; then
					echo "/jffs/scripts/$SCRIPT_NAME startup"' "$@" & # '"$SCRIPT_NAME" >> /jffs/scripts/post-mount
				fi
			else
				echo "#!/bin/sh" > /jffs/scripts/post-mount
				echo "" >> /jffs/scripts/post-mount
				echo "/jffs/scripts/$SCRIPT_NAME startup"' "$@" & # '"$SCRIPT_NAME" >> /jffs/scripts/post-mount
				chmod 0755 /jffs/scripts/post-mount
			fi
		;;
		delete)
			if [ -f /jffs/scripts/post-mount ]; then
				STARTUPLINECOUNT=$(grep -c '# '"$SCRIPT_NAME" /jffs/scripts/post-mount)
				
				if [ "$STARTUPLINECOUNT" -gt 0 ]; then
					sed -i -e '/# '"$SCRIPT_NAME"'/d' /jffs/scripts/post-mount
				fi
			fi
		;;
	esac
}

Auto_Cron(){
	case $1 in
		create)
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_check")
			if [ "$STARTUPLINECOUNT" -eq 0 ]; then
				cru a "${SCRIPT_NAME}_check" "10 0 * * * /jffs/scripts/$SCRIPT_NAME check"
			fi
		;;
		daily)
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_daily")
			if [ "$STARTUPLINECOUNT" -eq 0 ]; then
				cru a "${SCRIPT_NAME}_daily" "30 0 * * * /jffs/scripts/$SCRIPT_NAME daily"
			fi
		;;
		weekly)
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_weekly")
			if [ "$STARTUPLINECOUNT" -eq 0 ]; then
				cru a "${SCRIPT_NAME}_weekly" "35 0 * * 0 /jffs/scripts/$SCRIPT_NAME weekly"
			fi
			
		;;
		delete)
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_check")
			if [ "$STARTUPLINECOUNT" -gt 0 ]; then
				cru d "${SCRIPT_NAME}_check"
			fi
			
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_daily")
			if [ "$STARTUPLINECOUNT" -gt 0 ]; then
				cru d "${SCRIPT_NAME}_daily"
			fi

			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_weekly")
			if [ "$STARTUPLINECOUNT" -gt 0 ]; then
				cru d "${SCRIPT_NAME}_weekly"
			fi
		;;
		deletedaily)
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_daily")
			if [ "$STARTUPLINECOUNT" -gt 0 ]; then
				cru d "${SCRIPT_NAME}_daily"
			fi
			STARTUPLINECOUNT=$(cru l | grep -c "${SCRIPT_NAME}_weekly")
			if [ "$STARTUPLINECOUNT" -gt 0 ]; then
				cru d "${SCRIPT_NAME}_weekly"
			fi
		;;

	esac
}

Download_File(){
	/usr/sbin/curl -fsL --retry 3 "$1" -o "$2"
}

Shortcut_Script(){
	case $1 in
		create)
			if [ -d /opt/bin ] && [ ! -f "/opt/bin/$SCRIPT_NAME" ] && [ -f "/jffs/scripts/$SCRIPT_NAME" ]; then
				ln -s "/jffs/scripts/$SCRIPT_NAME" /opt/bin
				chmod 0755 "/opt/bin/$SCRIPT_NAME"
			fi
		;;
		delete)
			if [ -f "/opt/bin/$SCRIPT_NAME" ]; then
				rm -f "/opt/bin/$SCRIPT_NAME"
			fi
		;;
	esac
}

PressEnter(){
	while true; do
		printf "Press enter to continue..."
		read -r key
		case "$key" in
			*)
				break
			;;
		esac
	done
	return 0
}

Check_Requirements(){
	CHECKSFAILED="false"

	if [ "$(nvram get jffs2_scripts)" -ne 1 ]; then
		nvram set jffs2_scripts=1
		nvram commit
		Print_Output true "Custom JFFS Scripts enabled" "$WARN"
	fi

	if [ ! -f /opt/bin/opkg ]; then
		Print_Output false "Entware not detected!" "$ERR"
		CHECKSFAILED="true"
	fi

	if ! Firmware_Version_Check; then
		Print_Output false "Unsupported firmware version detected" "$ERR"
		Print_Output false "$SCRIPT_NAME requires Merlin 384.15/384.13_4 or Fork 43E5 (or later)" "$ERR"
		CHECKSFAILED="true"
	fi

	if [ "$CHECKSFAILED" = "false" ]; then
#		Print_Output false "Installing required packages from Entware" "$PASS"
#		opkg update
		return 0
	else
		return 1
	fi
}

ScriptStorageLocation(){

	MTDFILELIST="mtddevs mtdlog mtdmonlist mtdreport mtdweekly lastresult"

	case "$1" in
		usb)
			sed -i 's/^STORAGELOCATION.*$/STORAGELOCATION=usb/' "$SCRIPT_CONF"
			mkdir -p "/opt/share/$SCRIPT_NAME.d/"
			mv "/jffs/addons/$SCRIPT_NAME.d/mtdmon.conf" "/opt/share/$SCRIPT_NAME.d/" 2>/dev/null
			mv "/jffs/addons/$SCRIPT_NAME.d/mtdmon.conf.bak" "/opt/share/$SCRIPT_NAME.d/" 2>/dev/null
			for i in $MTDFILELIST
			do
				mv "/jffs/addons/$SCRIPT_NAME.d/$i" "/opt/share/$SCRIPT_NAME.d/" 2>/dev/null
			done
			SCRIPT_CONF="/opt/share/$SCRIPT_NAME.d/mtdmon.conf"
			ScriptStorageLocation load
		;;
		jffs)
			sed -i 's/^STORAGELOCATION.*$/STORAGELOCATION=jffs/' "$SCRIPT_CONF"
			mkdir -p "/jffs/addons/$SCRIPT_NAME.d/"
			mv "/opt/share/$SCRIPT_NAME.d/mtdmon.conf" "/jffs/addons/$SCRIPT_NAME.d/" 2>/dev/null
			mv "/opt/share/$SCRIPT_NAME.d/mtdmon.conf.bak" "/jffs/addons/$SCRIPT_NAME.d/" 2>/dev/null
			for i in $MTDFILELIST
			do
				mv "/opt/share/$SCRIPT_NAME.d/$i" "/jffs/addons/$SCRIPT_NAME.d/" 2>/dev/null
			done
			SCRIPT_CONF="/jffs/addons/$SCRIPT_NAME.d/mtdmon.conf"
			ScriptStorageLocation load
		;;
		check)
			STORAGELOCATION=$(grep "STORAGELOCATION" "$SCRIPT_CONF" | cut -f2 -d"=")
			echo "$STORAGELOCATION"
		;;
		load)
			STORAGELOCATION=$(grep "STORAGELOCATION" "$SCRIPT_CONF" | cut -f2 -d"=")
			if [ "$STORAGELOCATION" = "usb" ]; then
				SCRIPT_STORAGE_DIR="/opt/share/$SCRIPT_NAME.d"
			elif [ "$STORAGELOCATION" = "jffs" ]; then
				SCRIPT_STORAGE_DIR="/jffs/addons/$SCRIPT_NAME.d"
			fi
			TO_SMS=$(grep "TO_SMS" "$SCRIPT_CONF" | cut -f2 -d"=")
			SENDSMS=$(grep "SENDSMS" "$SCRIPT_CONF" | cut -f2 -d"=")
			ERROREMAIL=$(grep "ERROREMAIL" "$SCRIPT_CONF" | cut -f2 -d"=")
#			CSV_OUTPUT_DIR="$SCRIPT_STORAGE_DIR/csv"
			MTDMON_OUTPUT_FILE="$SCRIPT_STORAGE_DIR/mtdmon.txt"
		;;
	esac
}

OutputTimeMode(){
	case "$1" in
		unix)
			sed -i 's/^OUTPUTTIMEMODE.*$/OUTPUTTIMEMODE=unix/' "$SCRIPT_CONF"
#			Generate_CSVs
		;;
		non-unix)
			sed -i 's/^OUTPUTTIMEMODE.*$/OUTPUTTIMEMODE=non-unix/' "$SCRIPT_CONF"
#			Generate_CSVs
		;;
		check)
			OUTPUTTIMEMODE=$(grep "OUTPUTTIMEMODE" "$SCRIPT_CONF" | cut -f2 -d"=")
			echo "$OUTPUTTIMEMODE"
		;;
	esac
}

Generate_CSVs(){
	return 0
}

Generate_Stats(){
	Create_Dirs
	Conf_Exists
	ScriptStorageLocation load
	Auto_Cron create 2>/dev/null
	Shortcut_Script create
	TZ=$(cat /etc/TZ)
	export TZ
	printf "mtdmon stats as of: %s\\n\\n" "$(date)" > "$MTDMON_OUTPUT_FILE"
	mtdev="/dev/mtd0"
	printf "Running chk_mtd on $s" $mtdev
	if [ "$1" = "Verbose" ]; then
		cflags=""
	else
		cflags="-e"
	fi
	{
		$MTD_CHECK_COMMAND $cflags $mtdev;
	} >> "$MTDMON_OUTPUT_FILE"
	[ -z "$2" ] && cat "$MTDMON_OUTPUT_FILE"
	[ -z "$2" ] && printf "\\n"
	[ -z "$2" ] && Print_Output false "mtdmon summary generated" "$PASS"
}

Generate_Email(){

	if [ "$DAILYEMAIL" = "none" ]; then
		return 1
	fi

	if [ -f /jffs/addons/amtm/mail/email.conf ] && [ -f /jffs/addons/amtm/mail/emailpw.enc ]; then
		. /jffs/addons/amtm/mail/email.conf
		PWENCFILE=/jffs/addons/amtm/mail/emailpw.enc
	else
		Print_Output true "$SCRIPT_NAME relies on amtm to send email summaries and email settings have not been configured" "$ERR"
		Print_Output true "Navigate to amtm > em (email settings) to set them up" "$ERR"
		return 1
	fi
	
	PASSWORD=""
	if /usr/sbin/openssl aes-256-cbc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# old OpenSSL 1.0.x
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	elif /usr/sbin/openssl aes-256-cbc -d -md md5 -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# new OpenSSL 1.1.x non-converted password
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc -d -md md5 -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	elif /usr/sbin/openssl aes-256-cbc $emailPwEnc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# new OpenSSL 1.1.x converted password with -pbkdf2 flag
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc $emailPwEnc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	fi
	
	emailtype="$1"
	
	if [ "$emailtype" = "daily" ] || [ "$emailtype" = "weekly" ]; then
		Print_Output true "Attempting to send daily/weekly check email"
			# plain text email to send or text #
			{
				echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
				echo "To: \"$TO_NAME\" <$TO_ADDRESS>"
				if [ "$emailtype" = "daily" ]; then
					echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon daily stats as of $(date +"%H.%M on %F")"
				else
					echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon weekly stats as of $(date +"%H.%M on %F")"
				fi
				echo "Date: $(date -R)"
				echo ""
			} > /tmp/mail.txt
			if [ "$emailtype" = "daily" ]; then
				cat "$MTDREPORT" >>/tmp/mail.txt
				if [ -f "$MTDERRORS" ]; then
					cat $MTDERRORS >> /tmp/mail.txt
				fi
			else
				cat "$MTDWEEKLY" >>/tmp/mail.txt
				if [ -f "$MTDERRORS" ]; then
					cat $MTDERRORS >> /tmp/mail.txt
				fi
			fi
	elif [ "$emailtype" = "error" ]; then
		Print_Output true "Attempting to send error email"
			# plain text emails to send #
			{
				echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
				echo "To: \"$TO_NAME\" <$TO_ADDRESS>"
				echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon Detected Error(s) as of $(date +"%H.%M on %F")"
				echo "Date: $(date -R)"
				echo ""
			} > /tmp/mail.txt
			if [ -f "$MTDERRORS" ]; then
				cat $MTDERRORS >> /tmp/mail.txt
			fi
			cat "$MTDREPORT" >>/tmp/mail.txt
	elif [ "$emailtype" = "test" ]; then
		Print_Output true "Attempting to send test email"
			# plain text email to send #
			{
				echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
				echo "To: \"$TO_NAME\" <$TO_ADDRESS>"
				echo "Subject: $FRIENDLY_ROUTER_NAME - successful mtdmon Email test"
				echo ""
			} > /tmp/mail.txt
			echo "" >> /tmp/mail.txt
	fi
	
	#Send Email or sms
	/usr/sbin/curl -s --show-error --url "$PROTOCOL://$SMTP:$PORT" \
	--mail-from "$FROM_ADDRESS" --mail-rcpt "$TO_ADDRESS" \
	--upload-file /tmp/mail.txt \
	--ssl-reqd \
	--user "$USERNAME:$PASSWORD" $SSL_FLAG
	if [ $? -eq 0 ]; then
		echo ""
		[ -z "$5" ] && Print_Output true "Message sent successfully" "$PASS"
if [ $debug = 0 ]; then
		rm -f /tmp/mail.txt
fi
		PASSWORD=""
		return 0
	else
		echo ""
		[ -z "$5" ] && Print_Output true "Message failed to send" "$ERR"
if [ $debug = 0 ]; then
		rm -f /tmp/mail.txt
fi
		PASSWORD=""
		return 1
	fi
}

Generate_Message(){

	if [ "$SENDSMS" = "no" ]; then
		return 1
	fi

	if [ -f /jffs/addons/amtm/mail/email.conf ] && [ -f /jffs/addons/amtm/mail/emailpw.enc ]; then
		. /jffs/addons/amtm/mail/email.conf
		PWENCFILE=/jffs/addons/amtm/mail/emailpw.enc
	else
		Print_Output true "$SCRIPT_NAME relies on amtm to send email summaries and email settings have not been configured" "$ERR"
		Print_Output true "Navigate to amtm > em (email settings) to set them up" "$ERR"
		return 1
	fi
	
	PASSWORD=""
	TO_SMS=$(grep "TO_SMS" "$SCRIPT_CONF" | cut -f2 -d"=")
	if /usr/sbin/openssl aes-256-cbc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# old OpenSSL 1.0.x
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	elif /usr/sbin/openssl aes-256-cbc -d -md md5 -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# new OpenSSL 1.1.x non-converted password
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc -d -md md5 -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	elif /usr/sbin/openssl aes-256-cbc $emailPwEnc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi >/dev/null 2>&1 ; then
		# new OpenSSL 1.1.x converted password with -pbkdf2 flag
		PASSWORD="$(/usr/sbin/openssl aes-256-cbc $emailPwEnc -d -in "$PWENCFILE" -pass pass:ditbabot,isoi 2>/dev/null)"
	fi
	
	smstype="$1"
	
	if [ "$smstype" = "daily" ] && [ "$SENDSMS" = "daily" ]; then
		Print_Output true "Attempting to send daily/weekly sms message"
		# plain text email to send or text #
		{
		echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
		echo "To: <$TO_SMS>"
		echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon daily check as of $(date +"%H.%M on %F") - OK"
		echo ""
		} > /tmp/smsmail.txt
	elif [ "$smstype" = "error" ]; then
		Print_Output true "Attempting to send error sms message"
		# plain text email/sms to send #
		{
		echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
		echo "To: \"$TO_NAME\" <$TO_SMS>"
		echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon Detected Error(s) as of $(date +"%H.%M on %F")"
		echo ""
		} > /tmp/smsmail.txt
	elif [ "$smstype" = "test" ]; then
		Print_Output true "Attempting to send test sms email"
		# plain text email/sms to send #
		{
		echo "From: \"$FRIENDLY_ROUTER_NAME\" <$FROM_ADDRESS>"
		echo "To: \"$TO_NAME\" <$TO_SMS>"
		echo "Subject: $FRIENDLY_ROUTER_NAME - mtdmon successful sms test as of $(date +"%H.%M on %F")"
		echo ""
		} > /tmp/smsmail.txt
	fi
	
	#Send SMS via Email
	/usr/sbin/curl -s --show-error --url "$PROTOCOL://$SMTP:$PORT" \
	--mail-from "$FROM_ADDRESS" --mail-rcpt "$TO_SMS" \
	--upload-file /tmp/smsmail.txt \
	--ssl-reqd \
	--user "$USERNAME:$PASSWORD" $SSL_FLAG
	if [ $? -eq 0 ]; then
		echo ""
		[ -z "$5" ] && Print_Output true "Message sent successfully" "$PASS"
if [ $debug = 0 ]; then
		rm -f /tmp/mail.txt
fi
		PASSWORD=""
		return 0
	else
		echo ""
		[ -z "$5" ] && Print_Output true "Message failed to send" "$ERR"
if [ $debug = 0 ]; then
		rm -f /tmp/mail.txt
fi
		PASSWORD=""
		return 1
	fi
}


# encode image for email inline
# $1 : image content id filename (match the cid:filename.png in html document)
# $2 : image content base64 encoded
# $3 : output file
Encode_Image(){
	{
		echo "";
		echo "--MULTIPART-RELATED-BOUNDARY";
		echo "Content-Type: image/png;name=\"$1\"";
		echo "Content-Transfer-Encoding: base64";
		echo "Content-Disposition: inline;filename=\"$1\"";
		echo "Content-Id: <$1>";
		echo "";
		echo "$2";
	} >> "$3"
}

# encode text for email inline
# $1 : text content base64 encoded
# $2 : output file
Encode_Text(){
	{
		echo "";
		echo "--MULTIPART-RELATED-BOUNDARY";
		echo "Content-Type: text/plain;name=\"$1\"";
		echo "Content-Transfer-Encoding: quoted-printable";
		echo "Content-Disposition: attachment;filename=\"$1\"";
		echo "";
		echo "$2";
	} >> "$3"
}

DailyEmail(){
	case "$1" in
		enable)
			if [ -z "$2" ]; then
				ScriptHeader
				exitmenu="false"
				GetEmailOption
				printf "\\n${BOLD}mtdmon can send an email when it detects an error:${CLEARFORMAT}\\n"
				printf "${BOLD}It can also email a daily or weekly report:${CLEARFORMAT}\\n"
				printf "The present setting is $MENU_DAILYEMAIL ${CLEARFORMAT}\\n\\n"
				printf "1.    Only when an error is detected\\n"
				printf "2.    Weekly (and also when an error is detected\\n"
				printf "3.    Daily (and also when an error is detected\\n"
				printf "4.    Don't send any emails\\n"
				printf "\\ne.    Exit to main menu\\n"
				
				while true; do
					printf "\\n${BOLD}Choose an option:${CLEARFORMAT}  "
					read -r emailtype
					case "$emailtype" in
						1)
							sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL=error/' "$SCRIPT_CONF"
							break
						;;
						2)
							sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL=weekly/' "$SCRIPT_CONF"
							Auto_Cron weekly
							break
						;;
						3)
							sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL=daily/' "$SCRIPT_CONF"
							Auto_Cron daily
							break
						;;
						4)
							sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL=none/' "$SCRIPT_CONF"
							Auto_Cron deletedaily
							break
						;;
						e)
							exitmenu="true"
							break
						;;
						*)
							printf "\\nPlease choose a valid option\\n\\n"
						;;
					esac
				done
				
				printf "\\n"
				
				if [ "$exitmenu" = "true" ]; then
					return
				fi
			else
				sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL='"$2"'/' "$SCRIPT_CONF"
			fi
			
#			Generate_Email daily
#			if [ $? -eq 1 ]; then
#				DailyEmail disable
#			fi
		;;
		disable)
			sed -i 's/^DAILYEMAIL.*$/DAILYEMAIL=none/' "$SCRIPT_CONF"
		;;
		check)
			DAILYEMAIL=$(grep "DAILYEMAIL" "$SCRIPT_CONF" | cut -f2 -d"=")
			echo "$DAILYEMAIL"
		;;
		type)
			EMAILTYPE=$(grep "EMAILTYPE" "$SCRIPT_CONF" | cut -f2 -d"=")
			echo "$EMAILTYPE"

		;;
	esac
}


SetSMSAddr(){
	case "$1" in
		set)
			printf "\\nPlease enter your SMS email address in the form:\\n\\n"
			printf "\\n${BOLD}    1234567890@mobilegw.com.${CLEARFORMAT}\\n"
			printf "\\n\\nWhere 1234567890 is your 10 digit mobile number and moblilegw.com is your mobile carriers SMS gateway\\n"
			printf "The 10 digit mobile number is the most common. Check with your carrier.\\n"
			printf "In some cases, the 10 digit number might be shorter or require a pin or code\\n"
			printf "mtdmon will do very little checking on the entered address. Best to run a test message from the menu when done!\\n"
			printf "\\nPlease enter the address: "
			read inadd
			addln=`echo $inadd | awk '{print length}'`
			if [ $addln -gt 8 ]; then
				TO_SMS=$inadd
			else
				printf "\\nThe length of $inadd seems too small\\n"
				sleep 3
				exit
			fi
				
			sed -i 's/^TO_SMS.*$/TO_SMS='"$TO_SMS"'/' "$SCRIPT_CONF"
		;;
		show)
			echo $TO_SMS
		;;
		reset)
				TO_SMS=none
				sed -i 's/^TO_SMS.*$/TO_SMS=none/' "$SCRIPT_CONF"
		;;
	esac
}


SetUpSMS(){
	case "$1" in
		enable)
			if [ -z "$2" ]; then
				ScriptHeader
				exitmenu="false"
				printf "\\n${BOLD}mtdmon can also send a txt message via email when it detects an error.${CLEARFORMAT}\\n"
				printf "${BOLD}It can also send a daily text as well as an error.${CLEARFORMAT}\\n"
				printf "\\nTo send a text message via email, you must use a SMS or MMS to email gateway (email address).\\n"
				printf "Just substitute your 10-digit cell phone number followed by the SMS gateway of your mobile provider\\n"
				printf "\\n For example, if your US mobile number is (123) 456-7890 and your mobile provider is Verizon\\n"
				printf "\\n the address would be:   1234567890@vtext.com\\n"
				printf "\\n${BOLD}For a list of mobile carrier SMS gateways, check:\\n     https://avtech.com/articles/138/list-of-email-to-sms-addresses/ .${CLEARFORMAT}\\n\\n"
				if [ $TO_SMS = "none" ]; then
					printf "\\nThere is no address setup. Setup now? (Y/N) "
					read r
					case "$r" in
						y) SetSMSAddr set
						   break
						;;
						Y) SetSMSAddr set
						   break
						;;
						*)
						   printf "\\nYou will need to setup a valid SMS address\\n"
						   sleep 3
						   exit
						;;
					esac
				fi
				printf "\\nYour present SMS email address is ${BOLD} $TO_SMS ${CLEARFORMAT}\\n"
				printf "Your present SMS option is ${BOLD} $SENDSMS ${CLEARFORMAT}\\n\\n"
				printf "1.    Only send when an error is detected\\n"
				printf "2.    Send Daily (and also when an error is detected\\n"
				printf "3.    Change SMS email address\\n"
				printf "4.    Stop sending SMS messages\\n"
				printf "5.    Send a test message\\n"
				printf "\\ne.    Exit to main menu\\n"
				
				while true; do
					printf "\\n${BOLD}Choose an option:${CLEARFORMAT}  "
					read -r smstype
	 				case "$smstype" in
						1)
							sed -i 's/^SENDSMS.*$/SENDSMS=yes/' "$SCRIPT_CONF"
							SENDSMS=yes
							break
						;;
						2)
							sed -i 's/^SENDSMS.*$/SENDSMS=daily/' "$SCRIPT_CONF"
							SENDSMS=daily
							break
						;;
						3)
							SetSMSAddr set
							break
						;;
						4)
							sed -i 's/^SENDSMS.*$/SENDSMS=no/' "$SCRIPT_CONF"
							SENDSMS=no
							break
						;;
						5)
							Generate_Message test
							break
						;;
						e)
							exitmenu="true"
							break
						;;
						*)
							printf "\\nPlease choose a valid option\\n\\n"
						;;
					esac
				done
				
				printf "\\n"
				
				if [ "$exitmenu" = "true" ]; then
					return
				fi
			else
				sed -i 's/^SENDSMS.*$/SENDSMS='"$2"'/' "$SCRIPT_CONF"
			fi
			
		;;
		disable)
			sed -i 's/^SENDSMS.*$/SENDSMS=no/' "$SCRIPT_CONF"
			SENDSMS=no
		;;
		check)
			SENDSMS=$(grep "SENDSMS" "$SCRIPT_CONF" | cut -f2 -d"=")
			echo "$SENDSMS"
		;;
	esac
}


# start of mtdmon functions


GetMTDDevs() {
cat /proc/mtd | grep -v 'ubi\|dev' > /tmp/mtdevs
rm -f $MTDEVPART
while IFS=  read -r line
     do
        mtdevice="$(echo $line | cut -d':' -f1)"
        mtpoint="$(echo $line | cut -d' ' -f4)"
#
# now, make sure they contain a valid nand that supports Bad Blocks and ECC
#
	if `$MTD_CHECK_COMMAND -i /dev/$mtdevice > /dev/null 2>&1`
	then
		echo "$mtdevice $mtpoint" >> $MTDEVPART
	fi
done < /tmp/mtdevs

# clean up quotes

sed -i 's/\"//g' $MTDEVPART

# Find jffs parition and replace its name

jffsp=`awk -v jffsd="/jffs" '$2==jffsd {print $1}' /proc/mounts | sed 's/block//' | cut -d '/' -f 3`
jffsmt=`cat $MTDEVPART | grep $jffsp | awk '{print $2 }'`
sed -i "s/$jffsmt/jffs/g" $MTDEVPART

}


SetMTDs() {
	
	rm -f $MTDMONLIST
	if [ ! -f $MTDEVPART ];
	then
		GetMTDDevs
	fi
	cp $MTDEVPART $MTDMONLIST
	
	case $1 in
		all)
			break
		;;
		user)
			Set_Edit
			$texteditor $MTDMONLIST
			break
		;;
		recommended)
			rm -f $MTDMONLIST
			if [ $ISHND == 1 ];
			then
				validmtds="rootfs data nvram image bootfs jffs misc1 misc2 misc3"
			else
				validmtds="brcmnand asus jffs"
			fi

			for i in $validmtds
			do
				grep -w $i $MTDEVPART | awk  '{ print $1, $2 }' >> $MTDMONLIST
			done
			break
		;;
	esac

}

	
SetMTDList() {

	GetMTDDevs

	exitmenu="false"

	printf "\\nMtdmon can monitor most all mtd devices or a user defined list\\n"
	printf "There are some mtd devices mtdmon can't check (using check_mtd) such as UBI formatted devices.\\n"
	printf "It is recommended at a minimum to monitor most devices/partitons such as nvram, bootfs, asus and image partitions (devices)\\n"
	printf "\\n${BOLD}    Not all routers have all of these devices/partitions!${CLEARFORMAT}\\n\\n"
	printf "Mtdmon will automatically select the recommended devices when installed or from menu option 1 in the next menu. \\n\\n"
	printf "Having mtdmon monitor all testable devices is fine but takes a little longer and longer reports.\\n"
	PressEnter
	printf "\\nThe list of valid (checkable) mtd devices/partitions on this router are:\\n\\n"
	cat $MTDEVPART
	printf "\\n\\nmtdmon is presently monitoring:\\n\\n"
	cat $MTDMONLIST
	printf "\\n\\nChoose:\\n"
	printf "1.     Do recommended mtd devices\\n"
	printf "2.     Do All mtd devices\\n"
	printf "3.     Manually edit monitor list\\n"
	printf "4.     Show latest monitor list\\n"
	printf "e.     Exit to main menu\\n"
	while true; do
		printf "\\n${BOLD}Choose an option:${CLEARFORMAT}  "
		read -r mtdlist
		case "$mtdlist" in
			1)
				SetMTDs recommended
				break
			;;
			2)
#				GetMTDDevs
				SetMTDs all
				break
			;;
			3)
				SetMTDs user
				break
			
			;;
			4)
				cat $MTDMONLIST
				break
			;;
			e)
				exitmenu="true"
				break
			;;
			*)
				printf "\\nPlease choose a valid option\\n\\n"
			;;
		esac
	done
	
	if [ ! $exitmenu = "true" ]; then
		printf "\\n\\nThe list of mtd devices mtdmon will check:\\n"
		cat $MTDMONLIST
	fi
	printf "\\n"
}

CheckMTDList() {

	printf "Checking:\\n\\n"

       	if [ "$1" = "Verbose" ]; then
                cflags=""
        else
                cflags="-e"
        fi

	for mtdev in `cat $MTDMONLIST | awk '{ print $1}'`
		do
			printf "${BOLD}$mtdev "
			printf "`grep -w $mtdev $MTDMONLIST | awk '{print $2}'`${CLEARFORMAT}\\n"
        		$MTD_CHECK_COMMAND $cflags /dev/$mtdev
#			printf "\\n"
		done
	
}

CreateMTDLog(){
	rm -f $MTDLOG

	for i in `cat $MTDMONLIST | awk '{print $1}'`
	do
        	printf "$i   " >> $MTDLOG
		printf "`grep -w $i $MTDMONLIST | awk '{print $2}'`   " >> $MTDLOG
        	printf "`$MTD_CHECK_COMMAND -z /dev/$i` " >> $MTDLOG
        	printf "  `date +"%m-%d-%Y-%h-%m" `\\n" >> $MTDLOG
	done
}

ShowBBReport(){

	repdate=$(date +"%H.%M on %F")
	printf "\\nMtdmon Report $repdate\\n"
	printf "\\n\\nmtd dev\t   # Bad Blocks\t\t# Corr ECC\t# Uncorrectable ECC\\n"
	printf "-----------------------------------------------------------------\n"
        while IFS=  read -r line
        do
                mtdevice="$(echo $line | cut -d' ' -f1)"
                mtmnt="$(echo $line | cut -d' ' -f2)"
                numbbs="$(echo $line | cut -d' ' -f3)"
                numcorr="$(echo $line | cut -d' ' -f4)"
                numuncorr="$(echo $line | cut -d' ' -f5)"
		printf " $mtdevice\\t$mtmnt\\t\\t$numbbs\\t\\t  $numcorr\t\t  $numuncorr\\n" 
        done < $MTDLOG
}

ShowBBErrorReport(){


	if [ -f "$MTDERRLOG" ]; then
		repdate=$(date +"%H.%M on %F")
		printf "\\nMtdmon Error Report $repdate\\n"
		previouserrors=`cat $MTDERRLOG`
		printf "$previouserrors"
	else
		printf "\\nNo earlier errors detected\\n"
	fi

}


ReadCheckMTD(){

# read all of mtd device using block size and count
# if the # blocks read != # blocks on device return error
# $1 = mtd device $2 = "silent" if no printing

bsize=`$MTD_CHECK_COMMAND -i $1 | grep -w Block | awk '{ print $3 }'`
bcount=`$MTD_CHECK_COMMAND -i $1 | grep -w blocks | awk '{ print $5 }'`

# read blocks

if [ ! $2 = "silent" ]; then
	printf "Read Check $1"
fi

/bin/dd if=$1 of=/dev/null bs=$bsize count=$bcount > /tmp/mtddd 2>&1

readbs=`head -1 /tmp/mtddd | awk '{ print $1 }'`

if [ debug = 1 ]; then
	printf "Blocks Read: "$readbs" Blocks Expected: "$bcount+0" \\n"
fi

if [ ! "$readbs" = "$bcount+0" ]; then
	if [ ! $2 = "silent" ]; then
		printf "Did not read all blocks\\n"
		printf "Expected  $bcount+0    Got  $readbs\\n"
	fi
	return 1
fi
if [ ! $2 = "silent" ]; then
	printf " ok\\n"
fi
return 0
}


ScanBadBlocks(){

	cp $MTDLOG $MTDLOG.old    # save old results
	rm -f $MTDERRORS
	
	founderror=0
	newecc=0
	newuncor=0
	newebb=0
	readchk=0
	rsilent=0

	if [ "$1" = "readchks" ]; then
		readchk=1
		rsilent=1
	elif [ "$1" = readchk ]; then
		readchk=1
	fi

	newdate=$(date +"at %H.%M on %F")

	printf "\\nMtdmonReport Date $newdate\\n" > $MTDREPORT

	CreateMTDLog  ## create new log

        while IFS='' read -r line
        do
                mtdevice="$(echo $line | cut -d' ' -f1)"
                mtmnt="$(echo $line | cut -d' ' -f2)"
                numbbs="$(echo $line | cut -d' ' -f3)"
                numcorr="$(echo $line | cut -d' ' -f4)"
                numuncorr="$(echo $line | cut -d' ' -f5)"
                bbsdate="$(echo $line | cut -d' ' -f6)"

		if [ $readchk = 1 ] && [ $rsilent = 1 ]; then
			ReadCheckMTD /dev/$mtdevice silent
		elif [ $readchk = 1 ] && [ $rsilent = 0 ]; then
			ReadCheckMTD /dev/$mtdevice verbose
		fi

                latestinfo="$($MTD_CHECK_COMMAND -z /dev/$mtdevice)"    # check mtd device

		latestbbs=`echo $latestinfo | awk '{print $1}'`
		latestcorr=`echo $latestinfo | awk '{print $2}'`
		latestuncorr=`echo $latestinfo | awk '{print $3}'`

		Debug_Output false "$mtdevice info $latestinfo\\n"
		Debug_Output false "info latest: bb -- $latestbbs  corr $latestcorr uncor $latestuncorr\\n"
		Debug_Output false "info prev: bb -- $numbbs  corr $numcorr uncor $numuncorr\\n"

                if [ "$latestbbs" -gt "$numbbs" ]; then
			printf "New Bad Block(s) detected on $mtdevice  $mtmnt. Previous number: $numbbs, new number: $latestbbs\\n" >> $MTDERRORS
			founderror=1
			newbb=$((newbb+1))
		fi
                if [ "$latestcorr" -gt "$numcorr" ]; then
			printf "New Correctable ECC Error(s) detected on $mtdevice  $mtmnt. Previous number: $numcorr, new number: $latestcorr\\n" >> $MTDERRORS
			founderror=1
			newecc=$((newecc+1))
		fi
                if [ "$latestuncorr" -gt "$numuncorr" ]; then
			printf "New Uncorrectable ECC Error(s) detected on $mtdevice  $mtmnt. Previous number: $numuncorr, new number: $latestuncorr\\n" >> $MTDERRORS		founderror=1
			newuncor=$((newuncor+1))
		fi
         done < $MTDLOG.old
		if [ -f "$MTDERRORS" ]; then
			printf "$newdate - \\n" >> $MTDERRLOG
			cat $MTDERRORS >> $MTDERRLOG    # MTDERRORS latest, MTDERRLOG historic
		fi
		if [ $founderror == 0 ]; then
			printf "\\nMonitoring:\\n" >> $MTDREPORT
			cat $MTDMONLIST >> $MTDREPORT
			printf "\\nReport Date $newdate\\n" >> $MTDREPORT
			printf "\\n All monitored mtd devices checked, no new errors\\n" >> $MTDREPORT
			echo "\\n   Last check $newdate - no new errors" > $LASTRESULTS
		else
			echo "\\nErrors found during check at $newdate\\n Bad Blocks: $newbb  ECC Errors: $newecc  Uncorrectable ECC: $newuncor\\n" > $LASTRESULTS
			printf "\\nReported Errors:\\n" >> $MTDREPORT
			cat $MTDERRORS >> $MTDREPORT   #  add detail to report
		fi
		cat $MTDREPORT >> $MTDWEEKLY # save info to end of weekly report
		printf "\\n" >> $MTDREPORT
		printf "\\n" >> $MTDWEEKLY
}

mtdmon_check(){

	founderror=0
	ScanBadBlocks noread
	if [ $founderror = 1 ]; then
		Generate_Email error
		Generate_Message error
	fi

}
mtdmon_daily(){

	if [ "$1" = "daily" ]; then
		Generate_Email daily
		Generate_Message daily
	else
		Generate_Email weekly
		mv $MTDWEEKLY $MTDWEEKLY.lastweek
	fi
}


PrintLastResults(){
	printf "\\n"
	if [ -f "$LASTRESULTS" ]; then
		lastresult=`cat $LASTRESULTS`
		if [ $(grep -c "Error" $LASTRESULTS) -ne 0 ]; then
				printf "${ERR}    $lastresult${CLEARFORMAT}"
		else
				printf "${PASS}   $lastresult${CLEARFORMAT}"
		fi
	fi
	PrintErrors       # print detail if available
	printf "\\n"
}
PrintErrors(){
	if [ -f "$MTDERRORS" ]; then
		printf "\\nDetected Errors -"
		previouserrors=`cat $MTDERRORS`
		printf "$previouserrors"
	fi
	printf "\\n"
}

GetEmailOption(){

	MENU_DAILYEMAIL="$(DailyEmail check)"
	if [ "$MENU_DAILYEMAIL" = "error" ]; then
		MENU_DAILYEMAIL="${PASS}ENABLED -  for Error"
	elif [ "$MENU_DAILYEMAIL" = "daily" ]; then
		MENU_DAILYEMAIL="${PASS}ENABLED - Daily and Error"
	elif [ "$MENU_DAILYEMAIL" = "weekly" ]; then
		MENU_DAILYEMAIL="${PASS}ENABLED - Weekly and Error"
	elif [ "$MENU_DAILYEMAIL" = "none" ]; then
		MENU_DAILYEMAIL="${ERR}DISABLED"
	fi
}


GetSMSOption(){

	if  [ "$SENDSMS" = "no" ]; then
		DOSMS="${PASS}DISABLED"
	elif [ "$SENDSMS" = "yes" ]; then
		DOSMS="${PASS}ENABLED for Errors"
	else
		DOSMS="${PASS}ENABLED Weekly and Errors"
	fi
}


ScriptHeader(){
	clear
	printf "\\n"
	printf "${BOLD}##################################################${CLEARFORMAT}\\n"
	printf "${BOLD}##                                              ##${CLEARFORMAT}\\n"
	printf "${BOLD}##             mtdmon on Merlin                 ##${CLEARFORMAT}\\n"
	printf "${BOLD}##        for AsusWRT-Merlin routers            ##${CLEARFORMAT}\\n"
	printf "${BOLD}##                                              ##${CLEARFORMAT}\\n"
	printf "${BOLD}##             %s on %-11s            ##${CLEARFORMAT}\\n" "$SCRIPT_VERSION" "$ROUTER_MODEL"
	printf "${BOLD}##                                              ## ${CLEARFORMAT}\\n"
	printf "${BOLD}## https://github.com/JGrana01/mtdmonn          ##${CLEARFORMAT}\\n"
	printf "${BOLD}##                                              ##${CLEARFORMAT}\\n"
	printf "${BOLD}##################################################${CLEARFORMAT}\\n"
	printf "\\n"
}

MainMenu(){

	debug=0
	GetEmailOption
	GetSMSOption

	printf "mtdmon check results -\\n"
	PrintLastResults
	PrintErrors


	printf "1.    Check mtd for Bad Blocks and ECC now\\n\\n"
	printf "2.    Run Verbose mtd stats now\\n\\n"
	printf "3.    Run read check mtd and scan for errors now (takes a while)\\n\\n"
	printf "l.    View/Set list of mtd devies to monitor/check\\n\\n"
	printf "r.    Show a report of the most recent check\\n\\n"
	printf "re.   Show a report of errors detected \\n\\n"
	printf "se.   Setup/Change emails for error and daily or weekly summary \\n      Currently: ${BOLD}$MENU_DAILYEMAIL${CLEARFORMAT}\\n\\n"
	printf "sm.   Setup/Change SMS settings    Currently: ${BOLD}$DOSMS${CLEARFORMAT}\\n\\n"
	printf "v.    Edit mtdmon conf\\n\\n"
	printf "s.    Toggle storage location for stats and conf\\n      Current location is ${SETTING}%s${CLEARFORMAT} \\n\\n" "$(ScriptStorageLocation check)"
	printf "u.    Check for updates\\n"
	printf "uf.   Force update %s with latest version\\n\\n" "$SCRIPT_NAME"
	printf "e.    Exit menu for %s\\n\\n" "$SCRIPT_NAME"
	printf "z.    Uninstall %s\\n" "$SCRIPT_NAME"
	printf "\\n"
	printf "${BOLD}##################################################${CLEARFORMAT}\\n"
	printf "\\n"
	
	while true; do	
		printf "Choose an option:  "
		read -r menu
		case "$menu" in
			1)
				printf "\\n"
				if Check_Lock menu; then
					ScanBadBlocks noread
					CheckMTDList Info
					Clear_Lock
				fi
				PressEnter
				break
			;;
			2)
				printf "\\n"
				if Check_Lock menu; then
					CheckMTDList Verbose
					Clear_Lock
				fi
				PressEnter
				break
			;;
			3)
				printf "\\n"
				if Check_Lock menu; then
					ScanBadBlocks readchk
					CheckMTDList Info
					Clear_Lock
				fi
				PressEnter
				break
			;;
			l)
				printf "\\n"
				SetMTDList
				PressEnter
				break
			;;
			r)
				printf "\\n"
				ShowBBReport
				PressEnter
				break
			;;
			re)
				printf "\\n"
				ShowBBErrorReport
				PressEnter
				break
			;;
			se)
				printf "\\n"
				DailyEmail enable
				PressEnter
				break
			;;
			v)
				printf "\\n"
				if Check_Lock menu; then
					Menu_Edit
				fi
				break
			;;
			t)
				printf "\\n"
				if [ "$(OutputTimeMode check)" = "unix" ]; then
					OutputTimeMode non-unix
				elif [ "$(OutputTimeMode check)" = "non-unix" ]; then
					OutputTimeMode unix
				fi
				break
			;;
			sm)
				printf "\\n"
				SetUpSMS enable
				break
			;;
			m)
				printf "\\n"
				if [ "$SENDSMS" = "no" ]; then
					SENDSMS=yes
					sed -i 's/^SENDSMS.*$/SENDSMS=yes/' "$SCRIPT_CONF"
				elif [ "$SENDSMS" = "yes" ]; then
					SENDSMS=no
					sed -i 's/^SENDSMS.*$/SENDSMS=no/' "$SCRIPT_CONF"
				fi
				break
			;;
			s)
				printf "\\n"
				if [ "$(ScriptStorageLocation check)" = "jffs" ]; then
					ScriptStorageLocation usb
				elif [ "$(ScriptStorageLocation check)" = "usb" ]; then
					ScriptStorageLocation jffs
				fi
				break
			;;
			u)
				printf "\\n"
				if Check_Lock menu; then
					Update_Version
					Clear_Lock
				fi
				PressEnter
				break
			;;
			uf)
				printf "\\n"
				if Check_Lock menu; then
					Update_Version force
					Clear_Lock
				fi
				PressEnter
				break
			;;
			e)
				ScriptHeader
				printf "\\n${BOLD}Thanks for using %s!${CLEARFORMAT}\\n\\n\\n" "$SCRIPT_NAME"
				exit 0
			;;
			z)
				while true; do
					printf "\\n${BOLD}Are you sure you want to uninstall %s? (y/n)${CLEARFORMAT}  " "$SCRIPT_NAME"
					read -r confirm
					case "$confirm" in
						y|Y)
							Menu_Uninstall
							exit 0
						;;
						*)
							break
						;;
					esac
				done
			;;

# for debug use - remove when release
			don)
				debug=1
				PressEnter
				break
			;;
			doff)
				debug=0
				PressEnter
				break
			;;
			scan)
				CreateMTDLog
#				ScanBadBlocks readchks
				PressEnter
				break
			;;
			dd)
				ReadCheckMTD /dev/mtd0 verbose
				PressEnter
				break
			;;
	
			*)
				printf "\\nPlease choose a valid option\\n\\n"
			;;
		esac
	done
	
	ScriptHeader
	MainMenu
}

Menu_Install(){
	ScriptHeader
	Print_Output true "Welcome to $SCRIPT_NAME $SCRIPT_VERSION, a script by JGrana using Jack Yaz addon as template"
	sleep 1
	
	Print_Output false "Checking your router meets the requirements for $SCRIPT_NAME"
	
	if ! Check_Requirements; then
		Print_Output false "Requirements for $SCRIPT_NAME not met, please see above for the reason(s)" "$CRIT"
		PressEnter
		Clear_Lock
		rm -f "/jffs/scripts/$SCRIPT_NAME" 2>/dev/null
		exit 1
	fi
	
	printf "\\n"
	
	Create_Dirs
	Conf_Exists
	Set_Version_Custom_Settings local "$SCRIPT_VERSION"
	Set_Version_Custom_Settings server "$SCRIPT_VERSION"
	ScriptStorageLocation load
	
#	Update_File mtdmon
	Update_File mtd_check
	
	Auto_Cron create 2>/dev/null
	Shortcut_Script create
	Print_Output false "Setting recommended mtd devices and doing initial scan..."
	SetMTDs recommended
	CreateMTDLog
	Print_Output false "Done. You can see the initial scan results by selecting "r" on the main menu"
	PressEnter
	Clear_Lock
	ScriptHeader
	MainMenu
}

Menu_Startup(){
	if [ -z "$1" ]; then
		Print_Output true "Missing argument for startup, not starting $SCRIPT_NAME" "$WARN"
		exit 1
	elif [ "$1" != "force" ]; then
		if [ ! -f "$1/entware/bin/opkg" ]; then
			Print_Output true "$1 does not contain Entware, not starting $SCRIPT_NAME" "$WARN"
			exit 1
		else
			Print_Output true "$1 contains Entware, starting $SCRIPT_NAME" "$WARN"
		fi
	fi
	
	NTP_Ready
	
	Check_Lock
	
	if [ "$1" != "force" ]; then
		sleep 5
	fi
	Create_Dirs
	Conf_Exists
	ScriptStorageLocation load
	Auto_Cron create 2>/dev/null
	Shortcut_Script create
	GetMTDDevs
	Clear_Lock
}

Set_Edit() {
	texteditor=""
	exitmenu="false"
	
	printf "\\n${BOLD}A choice of text editors is available:${CLEARFORMAT}\\n"
	printf "1.    nano (recommended for beginners)\\n"
	printf "2.    vi\\n"
	printf "\\ne.    Exit to main menu\\n"
	
	while true; do
		printf "\\n${BOLD}Choose an option:${CLEARFORMAT}  "
		read -r editor
		case "$editor" in
			1)
				texteditor="nano -K"
				break
			;;
			2)
				texteditor="vi"
				break
			;;
			e)
				exitmenu="true"
				break
			;;
			*)
				printf "\\nPlease choose a valid option\\n\\n"
			;;
		esac
	done
}
	
Menu_Edit(){

	Set_Edit

	CONFFILE="$SCRIPT_STORAGE_DIR/mtdmon.conf"
	$texteditor "$CONFFILE"
	Clear_Lock
}

Menu_Uninstall(){
	if [ -n "$PPID" ]; then
		ps | grep -v grep | grep -v $$ | grep -v "$PPID" | grep -i "$SCRIPT_NAME" | grep generate | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1
	else
		ps | grep -v grep | grep -v $$ | grep -i "$SCRIPT_NAME" | grep generate | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1
	fi
	Print_Output true "Removing $SCRIPT_NAME..." "$PASS"
	Auto_Cron delete 2>/dev/null
	
	Shortcut_Script delete
	
	SETTINGSFILE="/jffs/addons/custom_settings.txt"
	sed -i '/mtdmon_version_local/d' "$SETTINGSFILE"
	sed -i '/mtdmon_version_server/d' "$SETTINGSFILE"
	
	rm -f "/jffs/scripts/$SCRIPT_NAME"
	rm -rf "$SCRIPT_DIR"
	Clear_Lock
	Print_Output true "Uninstall completed" "$PASS"
}

NTP_Ready(){
	if [ "$(nvram get ntp_ready)" -eq 0 ]; then
		Check_Lock
		ntpwaitcount=0
		while [ "$(nvram get ntp_ready)" -eq 0 ] && [ "$ntpwaitcount" -lt 600 ]; do
			ntpwaitcount="$((ntpwaitcount + 30))"
			Print_Output true "Waiting for NTP to sync..." "$WARN"
			sleep 30
		done
		if [ "$ntpwaitcount" -ge 600 ]; then
			Print_Output true "NTP failed to sync after 10 minutes. Please resolve!" "$CRIT"
			Clear_Lock
			exit 1
		else
			Print_Output true "NTP synced, $SCRIPT_NAME will now continue" "$PASS"
			Clear_Lock
		fi
	fi
}

### function based on @Adamm00's Skynet USB wait function ###
Entware_Ready(){
	if [ ! -f /opt/bin/opkg ]; then
		Check_Lock
		sleepcount=1
		while [ ! -f /opt/bin/opkg ] && [ "$sleepcount" -le 10 ]; do
			Print_Output true "Entware not found, sleeping for 10s (attempt $sleepcount of 10)" "$ERR"
			sleepcount="$((sleepcount + 1))"
			sleep 10
		done
		if [ ! -f /opt/bin/opkg ]; then
			Print_Output true "Entware not found and is required for $SCRIPT_NAME to run, please resolve" "$CRIT"
			Clear_Lock
			exit 1
		else
			Print_Output true "Entware found, $SCRIPT_NAME will now continue" "$PASS"
			Clear_Lock
		fi
	fi
}
### ###

Show_About(){
	cat <<EOF
About
  $SCRIPT_NAME will monitor for Bad Blocks and ECC (both Correctable and
  Uncorrectable) errors on the NAND based mtd device on the router.
  It requires the mtd_check utility and will install it if needed.
  The mtd devices are non-volitle areas that store the firmware, nvram
  and other semi-permanant things such as software, settings, etc.
  Over time, the OS might detect a problem with a block of this NAND.
  It will typically correct the issue or reallocate this block as a 
  Bad Block. This is not unusual and is somewhat normal.
  But, if the number of Bad Blocks increase, it could show a case where
  the NAND device (the mtd hardware) is going bad.
License
  $SCRIPT_NAME is free to use under the GNU General Public License
  version 3 (GPL-3.0) https://opensource.org/licenses/GPL-3.0
Help & Support
  https://github.com/JGrana01/$SCRIPT_NAME
Source code
  https://github.com/JGrana01/$SCRIPT_NAME
  https://github.com/JGrana01/mtd_check
EOF
	printf "\\n"
}
### ###

### function based on @dave14305's FlexQoS show_help function ###
Show_Help(){
	cat <<EOF
Available commands:
  $SCRIPT_NAME about              explains functionality
  $SCRIPT_NAME update             checks for updates
  $SCRIPT_NAME forceupdate        updates to latest version (force update)
  $SCRIPT_NAME install            installs script
  $SCRIPT_NAME uninstall          uninstalls script
  $SCRIPT_NAME generate           get latest data from mtdmon and mtd_check. 
  $SCRIPT_NAME summary            get daily summary data from mtdmon. runs automatically at end of day.
  $SCRIPT_NAME outputcsv          create CSVs from data (not enabled, future feature)
  $SCRIPT_NAME develop            switch to development branch
  $SCRIPT_NAME stable             switch to stable branch
EOF
	printf "\\n"
}
### ###

if [ -f "/opt/share/$SCRIPT_NAME.d/mtdmon.conf" ]; then
	SCRIPT_CONF="/opt/share/$SCRIPT_NAME.d/mtdmon.conf"
	SCRIPT_STORAGE_DIR="/opt/share/$SCRIPT_NAME.d"
else
	SCRIPT_CONF="/jffs/addons/$SCRIPT_NAME.d/mtdmon.conf"
	SCRIPT_STORAGE_DIR="/jffs/addons/$SCRIPT_NAME.d"
fi

CSV_OUTPUT_DIR="$SCRIPT_STORAGE_DIR/csv"

if [ -z "$1" ]; then
	NTP_Ready
	Entware_Ready
	Create_Dirs
	Conf_Exists
	ScriptStorageLocation load
	Auto_Cron create 2>/dev/null
	Shortcut_Script create
	ScriptHeader
	MainMenu
	exit 0
fi

case "$1" in
	install)
		Check_Lock
		Menu_Install
		sleep 3
		exit 0
	;;
	startup)
		Menu_Startup "$2"
		exit 0
	;;
	generate)
		NTP_Ready
		Entware_Ready
		Check_Lock
		Generate_CSVs
		Clear_Lock
		exit 0
	;;
	check)
		NTP_Ready
		Check_Lock
		mtdmon_check
		Clear_Lock
		exit 0
	;;
	daily)
		NTP_Ready
		Check_Lock
		mtdmon_daily "daily"
		Clear_Lock
		exit 0
	;;
	weekly)
		NTP_Ready
		Check_Lock
		mtdmon_daily "weekly"
		Clear_Lock
		exit 0
	;;
	outputcsv)
		NTP_Ready
		Entware_Ready
		Generate_CSVs
	;;
	update)
		Update_Version
		exit 0
	;;
	forceupdate)
		Update_Version force
		exit 0
	;;
	postupdate)
		Create_Dirs
		Conf_Exists
		ScriptStorageLocation load
		Auto_Cron create 2>/dev/null
		Shortcut_Script create
		Generate_CSVs
		Clear_Lock
		exit 0
	;;
	uninstall)
		Menu_Uninstall
		exit 0
	;;
	about)
		ScriptHeader
		Show_About
		exit 0
	;;
	help)
		echo "Got to help"
		ScriptHeader
		Show_Help
		exit 0
	;;
	develop)
		SCRIPT_BRANCH="tree/develop"
		SCRIPT_REPO="https://raw.githubusercontent.com/JGrana01/mtdmon/$SCRIPT_BRANCH"
		Update_Version force
		exit 0
	;;
	stable)
		SCRIPT_BRANCH="main"
		SCRIPT_REPO="https://raw.githubusercontent.com/JGrana01/mtdmon/$SCRIPT_BRANCH"
		Update_Version force
		exit 0
	;;
	*)
		ScriptHeader
		Print_Output false "Command not recognised." "$ERR"
		Print_Output false "For a list of available commands run: $SCRIPT_NAME help"
		exit 1
	;;
esac
