=== Counterespionage Firewall ===
Contributors: floodspark
Donate link: http://floodspark.com/donate.html
Tags: espionage, recon, reconnaissance, intelligence, intel, cybersecurity, defense, bots, fraud, security, hackers
Requires at least: 5.3.2
Tested up to: 6.0.1
Requires PHP: 7.0.33
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

The Floodspark Counterespionage Firewall (CEF) WordPress plugin helps you block reconnaissance or otherwise illegitimate traffic including hackers, bots, and scrapers.

== Description ==

Floodspark Counterespionage Firewall (CEF) helps you block reconnaissance or otherwise illegitimate traffic. CEF is like a web application firewall (WAF) but protects against intelligence gathering. CEF focuses on pre-attack protection and is designed to complement security plugins such as Wordfence or Sucuri.

CEF can:
* Fake out WPScan and bots by hiding your real usernames, instead supplying them with fake ones they will never be able to log in with.
* Prevent bots from logging in even with your real password.
* Defeat WPScan's aggressive plugin and theme scans, also causing the scanner to terminate.

...as well as detect:
* Tor browser, with minor delay
* Chrome Incognito, with minor delay, over HTTPS
* Firefox Private Browsing, with minor delay
* Chrome-Selenium in its default configuration, with minor delay
* cURL in its default configuration
* Wget in its default configuration
* HTTP methods other than GET, POST, and HEAD
* Proxy probing

== Frequently Asked Questions ==

= How can I test CEF's protection? =
Use the Docker version of WPScan and the commands below. When prompted whether to update the database, you shouldn't need to.

* To verify that CEF deceives WPScan's username scan, issue the following command:
	docker run -it --rm wpscanteam/wpscan --url http://[yourbloghere.com] --enumerate u

* To verify that CEF deceives WPScan's plugin scan, issue the following command:
	docker run -it --rm wpscanteam/wpscan --url http://[yourbloghere.com] --plugins-detection aggressive

* To verify that CEF deceives WPScan's theme scan, issue the following command:
	docker run -it --rm wpscanteam/wpscan --url http://[yourbloghere.com] --enumerate t

= Does CEF replace a Web Application Firewall (WAF)? = 

No. CEF and was specifically designed to leave protection against active web attacks to WAFs, which do it best.

= Does CEF replace a host firewall? =

No. CEF specializes in web-type intelligence and leaves the protection of other services to the host firewall.

= Should I keep my WAF and host firewall? =

Yes.

= Why use CEF then? =

CEF helps you **earlier in the cyber-attack chain, during the Reconnaissance stage,** to disrupt malicious research efforts. Remember, attacks do not necessarily correlate with the research origin(s).

= What is an Intent Indicator? =

An Intent Indicator is a trait derived from cyber threat intelligence that with high confidence indicates malicious intent. You do not need to activate every Intent Indicator powering CEF if for some reason one or more break your business traffic. E.g. A bank may want to block visitors using Tor to reduce fraud, while an online newspaper may recognize that readers and journalists have an interest in using Tor to avoid censorship and retribution.

= How is an Intent Indicator different than an Indicator of Compromise (IoC)? =

BLUF: An Intent Indicator is earlier than an IoC. 

An IOC indicates that a breach already took place, allowing you only to respond after the fact. Intent Indicators are the attacker’s traits, or Tactics, Techniques, and Procedures (TTPs), observable during the recon phase--traits, that with high confidence, would not belong to legitimate visitor traffic and behavior.

== Screenshots ==
1. Deceiving WPScan's username hunting. Real usernames were "admin", "admin2", "admin3", "admin4", "admin5". No hacker can log in with these faked usernames because they don't actually exist.
2. Defeating WPScan's plugin scan
3. Defeating WPScan's theme scan
4. Error message the visitor will receive for banned behavior or devices.
5. Defeating hackertarget.com's WordPress username enumeration scan
6. Recommended setting for Endurance Cache / Endurance Page Cache to avoid issues

== Changelog ==

= 1.5.2 = 
* Bug fix: no longer blocking on non-sensitive pages (caching issue)

= 1.5.1 = 
* Bug fix: async checks now also work for sites not located in the root folder

= 1.5.0 = 
* CEF now disrupts hacker attempts at plugin and theme gathering/harvesting/enumeration

= 1.4.0 =
* CEF now disrupts hacker attempts at username gathering/harvesting/enumeration

= 1.3.0 =
* Fakes most current version of PHP

= 1.2.0 =
* Permitted HTTP methods safelisting
* Block proxy probes
* Blocked message appears for bad visitors
* General fixes

= 1.1.0 = 
* Added Wget detection
* Commented out debugging/localhost settings

= 1.0 =
* Initial public release

== Upgrade Notice ==

= 1.5.0 = 
We tripled CEF's WordPress-specific defenses to include plugin and theme scanning protection on top of username protection.

= 1.4.0 =
CEF now hides your real usernames from hackers. [Read about this unique approach on our blog](https://floodspark.com/blog/information-warfare-vs-security-through-obscurity/)

= 1.3.0 = 
CEF now fakes the most current version of PHP to throw off attacker intelligence gathering.

= 1.2.0 = 
Additional detections are included in this release. Also a message will appear for blocked users.

= 1.1.0 = 
Additional detection implemented and a bug fix.

= 1.0 =
Initial public release

== How does this work? ==
So! A hacker's usual approach for hacking into WordPress sites includes using a tool like WPScan to find out usernames as well as which plugins and themes are installed. They'll try to guess passwords for the user account(s) and also check vulnerability/exploit databases for any known vulnerabilities in any of the installed plugins or themes, and then try to hack into the site through those.

But! We're aiming to disrupt that information gathering step of the attack. So when WPScan scans for usernames, we give out fake ones that don't exist. So all the password guessing attempts will be in vain. When WPScan scans for any of 88.5k plugins that might be installed, we respond that every one of them is installed. Same with themes--when WPScan scans for 400 themes, we assert that they too are all installed.

So the attacker then has so much data they don't know what to trust. And they'll launch attacks against plugins and themes that don't exist, so the exploits will never work.

PS, WPScan is a legit tool that we love and just use as an example.

== Cyber Intent Blog ==
The [Floodspark Cyber Intent Blog](http://floodspark.com/blog/) uses this plugin and is all about just that, cyber intent. Here we will cover the art and science of it and the developments in the Counterespionage Firewall (CEF) portfolio (CEF for WordPress and CEF Full) that turn these ideas into reality.

== Stay up to date ==
Stay up to date with developments in the Floodspark portfolio [@Floodspark](https://twitter.com/floodspark)

== Thank you == 
Feedback is greatly appreciated as we continue to shape Floodspark. Email us anytime - gs@floodspark.com. 
