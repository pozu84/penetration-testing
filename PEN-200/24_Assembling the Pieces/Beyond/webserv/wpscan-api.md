wpscan --url http://192.168.199.244 -e vp --api-token
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.199.244/ [192.168.199.244]
[+] Effective URL: http://192.168.199.244/main/
[+] Started: Sat May 25 07:29:56 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.52 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.199.244/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.199.244/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.199.244/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0.2 identified (Insecure, released on 2022-08-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.199.244/main/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |  - http://192.168.199.244/main/comments/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |
 | [!] 27 vulnerabilities identified:
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 6.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
 |
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 6.0.5
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 6.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP 5.6-6.3.1 - Contributor+ Stored XSS via Navigation Block
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/cd130bb3-8d04-4375-a89a-883af131ed3a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38000
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP 5.6-6.3.1 - Reflected XSS via Application Password Requests
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/da1419cc-d821-42d6-b648-bdb3c70d91f2
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Denial of Service via Cache Poisoning
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/6d80e09d-34d5-4fda-81cb-e703d0e56e4f
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/3615aea0-90aa-4f9a-9792-078a90af7f59
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Contributor+ Comment Disclosure
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39999
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Unauthenticated Post Author Email Disclosure
 |     Fixed in: 6.0.6
 |     References:
 |      - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5561
 |      - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 6.0.7
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 6.0.7
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.5.2 - Unauthenticated Stored XSS
 |     Fixed in: 6.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/1a5c5df1-57ee-4190-a336-b0266962078f
 |      - https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/

[+] WordPress theme in use: hello-elementor
 | Location: http://192.168.199.244/wp-content/themes/hello-elementor/
 | Last Updated: 2024-01-24T00:00:00.000Z
 | Readme: http://192.168.199.244/wp-content/themes/hello-elementor/readme.txt
 | [!] The version is out of date, the latest version is 3.0.1
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

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://192.168.199.244/wp-content/plugins/contact-form-7/
 | Last Updated: 2024-05-21T08:43:00.000Z
 | [!] The version is out of date, the latest version is 5.9.5
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Contact Form 7 < 5.8.4 - Authenticated (Editor+) Arbitrary File Upload
 |     Fixed in: 5.8.4
 |     References:
 |      - https://wpscan.com/vulnerability/70e21d9a-b1e6-4083-bcd3-7c1c13fd5382
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6449
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/5d7fb020-6acb-445e-a46b-bdb5aaf8f2b6
 |
 | [!] Title: Contact Form 7 < 5.9.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.9.2
 |     References:
 |      - https://wpscan.com/vulnerability/1c070a2c-2ab0-43bf-b10b-6575709918bc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2242
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/d5bf4972-424a-4470-a0bc-7dcc95378e0e
 |
 | Version: 5.6.3 (90% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.199.244/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.6.3
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.199.244/wp-content/plugins/contact-form-7/readme.txt

[+] elementor
 | Location: http://192.168.199.244/wp-content/plugins/elementor/
 | Last Updated: 2024-05-22T10:53:00.000Z
 | [!] The version is out of date, the latest version is 3.21.7
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 9 vulnerabilities identified:
 |
 | [!] Title: Elementor Website Builder < 3.12.2 - Admin+ SQLi
 |     Fixed in: 3.12.2
 |     References:
 |      - https://wpscan.com/vulnerability/a875836d-77f4-4306-b275-2b60efff1493
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0329
 |
 | [!] Title: Elementor Website Builder < 3.13.2 - Missing Authorization
 |     Fixed in: 3.13.2
 |     Reference: https://wpscan.com/vulnerability/0b68091c-6a05-4f81-a718-6ec139df2e96
 |
 | [!] Title: Elementor Website Builder < 3.16.5 - Authenticated (Contributor+) Stored Cross-Site Scripting via get_inline_svg()
 |     Fixed in: 3.16.5
 |     References:
 |      - https://wpscan.com/vulnerability/62b53acf-6551-4ea7-8727-039a3c9ba7ce
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-47505
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/b44ef21f-464e-487a-ba5a-fe889e4c488c
 |
 | [!] Title: Elementor Website Builder < 3.16.5 - Missing Authorization to Arbitrary Attachment Read
 |     Fixed in: 3.16.5
 |     References:
 |      - https://wpscan.com/vulnerability/e60f0f7e-4c3b-4107-803a-8e03526859ed
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-47504
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/c873c76a-144e-4945-8fa2-c9ffe0e3c061
 |
 | [!] Title: Elementor < 3.18.2 - Contributor+ Arbitrary File Upload to RCE via Template Import
 |     Fixed in: 3.18.2
 |     References:
 |      - https://wpscan.com/vulnerability/a6b3b14c-f06b-4506-9b88-854f155ebca9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48777
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/5b6d0a38-ac28-41c9-9da1-b30b3657b463
 |
 | [!] Title: Elementor < 3.19.1 - Authenticated(Contributor+) Arbitrary File Deletion and PHAR Deserialization
 |     Fixed in: 3.19.1
 |     References:
 |      - https://wpscan.com/vulnerability/4d7dfcc6-8c32-4e0d-b3bb-7e2685916e2b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24934
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/4915b769-9499-40ac-835e-279e3a910558
 |
 | [!] Title: Elementor Website Builder – More than Just a Page Builder < 3.19.0 - Authenticated (Contributor+) Stored Cross-Site Scripting via get_image_alt
 |     Fixed in: 3.19.0
 |     References:
 |      - https://wpscan.com/vulnerability/57af46d9-9a26-4085-9829-e0add7893332
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0506
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/4473d3f6-e324-40f5-b92b-167f76b17332
 |
 | [!] Title: Elementor Website Builder < 3.20.3 - Contributor+ DOM Stored XSS
 |     Fixed in: 3.20.3
 |     References:
 |      - https://wpscan.com/vulnerability/22e8d017-79f5-40c8-8a2c-e0ee42ba80c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2117
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/c8d7448a-b8a6-4b0b-92df-a15272fc56bf
 |
 | [!] Title: Elementor Website Builder < 3.22.0-beta2 - Contributor+ DOM Stored XSS
 |     Fixed in: 3.22.0-beta2
 |     References:
 |      - https://wpscan.com/vulnerability/8b8f30d6-bd11-4155-bfd2-3ac15248382b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-4619
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/c7e1028e-e04b-46c4-b574-889d9fc1069d
 |
 | Version: 3.7.7 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.199.244/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.7.7
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.199.244/wp-content/plugins/elementor/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.199.244/wp-content/plugins/elementor/readme.txt

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 21

[+] Finished: Sat May 25 07:30:04 2024
[+] Requests Done: 58
[+] Cached Requests: 4
[+] Data Sent: 13.409 KB
[+] Data Received: 21.528 MB
[+] Memory used: 246.953 MB
[+] Elapsed time: 00:00:08
