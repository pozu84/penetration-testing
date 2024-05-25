_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[32m[+][0m URL: http://192.168.199.244/ [192.168.199.244]
[32m[+][0m Effective URL: http://192.168.199.244/main/
[32m[+][0m Started: Sat May 25 07:37:58 2024

Interesting Finding(s):

[32m[+][0m Headers
 | Interesting Entry: Server: Apache/2.4.52 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[32m[+][0m XML-RPC seems to be enabled: http://192.168.199.244/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[32m[+][0m WordPress readme found: http://192.168.199.244/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[32m[+][0m The external WP-Cron seems to be enabled: http://192.168.199.244/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[32m[+][0m WordPress version 6.0.2 identified (Insecure, released on 2022-08-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.199.244/main/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |  - http://192.168.199.244/main/comments/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>

[32m[+][0m WordPress theme in use: hello-elementor
 | Location: http://192.168.199.244/wp-content/themes/hello-elementor/
 | Last Updated: 2024-01-24T00:00:00.000Z
 | Readme: http://192.168.199.244/wp-content/themes/hello-elementor/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 3.0.1
 | Style URL: http://192.168.199.244/wp-content/themes/hello-elementor/style.css
 | Style Name: Hello Elementor
 | Style URI: https://elementor.com/hello-theme/?utm_source=wp-themes&utm_campaign=theme-uri&utm_medium=wp-dash
 | Description: A plain-vanilla & lightweight theme for Elementor page builder...
 | Author: Elementor Team
 | Author URI: https://elementor.com/?utm_source=wp-themes&utm_campaign=author-uri&utm_medium=wp-dash
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 2.6.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.199.244/wp-content/themes/hello-elementor/style.css, Match: 'Version: 2.6.1'


[34m[i][0m Plugin(s) Identified:

[32m[+][0m akismet
 | Location: http://192.168.199.244/wp-content/plugins/akismet/
 | Latest Version: 5.3.2
 | Last Updated: 2024-03-21T00:55:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/akismet/, status: 500
 |
 | The version could not be determined.

[32m[+][0m classic-editor
 | Location: http://192.168.199.244/wp-content/plugins/classic-editor/
 | Last Updated: 2024-04-06T00:44:00.000Z
 | Readme: http://192.168.199.244/wp-content/plugins/classic-editor/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 1.6.3
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/classic-editor/, status: 403
 |
 | Version: 1.6.2 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/classic-editor/readme.txt

[32m[+][0m contact-form-7
 | Location: http://192.168.199.244/wp-content/plugins/contact-form-7/
 | Last Updated: 2024-05-21T08:43:00.000Z
 | Readme: http://192.168.199.244/wp-content/plugins/contact-form-7/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 5.9.5
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/contact-form-7/, status: 403
 |
 | Version: 5.6.3 (90% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.199.244/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.6.3
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/contact-form-7/readme.txt

[32m[+][0m duplicator
 | Location: http://192.168.199.244/wp-content/plugins/duplicator/
 | Last Updated: 2024-04-18T15:10:00.000Z
 | Readme: http://192.168.199.244/wp-content/plugins/duplicator/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 1.5.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/duplicator/, status: 403
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/duplicator/readme.txt

[32m[+][0m elementor
 | Location: http://192.168.199.244/wp-content/plugins/elementor/
 | Last Updated: 2024-05-22T10:53:00.000Z
 | Readme: http://192.168.199.244/wp-content/plugins/elementor/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 3.21.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/elementor/, status: 403
 |
 | Version: 3.7.7 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.199.244/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.7.7
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.199.244/wp-content/plugins/elementor/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.199.244/wp-content/plugins/elementor/readme.txt

[32m[+][0m wordpress-seo
 | Location: http://192.168.199.244/wp-content/plugins/wordpress-seo/
 | Last Updated: 2024-05-14T08:05:00.000Z
 | Readme: http://192.168.199.244/wp-content/plugins/wordpress-seo/readme.txt
 | [33m[!][0m The version is out of date, the latest version is 22.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/wordpress-seo/, status: 200
 |
 | Version: 19.7.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/wordpress-seo/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/wordpress-seo/readme.txt

[33m[!][0m No WPScan API Token given, as a result vulnerability data has not been output.
[33m[!][0m You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[32m[+][0m Finished: Sat May 25 07:38:31 2024
[32m[+][0m Requests Done: 1522
[32m[+][0m Cached Requests: 50
[32m[+][0m Data Sent: 425.05 KB
[32m[+][0m Data Received: 532.13 KB
[32m[+][0m Memory used: 232.691 MB
[32m[+][0m Elapsed time: 00:00:33
