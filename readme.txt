=== Einfaches Kontaktformular ===
Tags: contact form, block, smtp, honeypot
Requires at least: 6.3
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.2.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A contact form block with authenticated SMTP, a honeypot, and server-side spam checks.

== Description ==

Add the contact form block to a page and configure your own SMTP server. The form supports German, English, Spanish, Simplified Chinese, and Hindi.

Spam checks include a honeypot, per-IP rate limiting, and rejection of messages made up only of digits and common number separators. Short messages and messages containing both words and numbers are accepted.

= Privacy and SMTP =

The plugin sends the visitor's name, email address, and message to the configured recipient through the SMTP server chosen by the site administrator. The SMTP provider handles the delivery and may retain messages or logs under its own terms. There is no bundled SMTP service.

WordPress stores the SMTP settings, including the password in the database, and the latest delivery status. Form messages are sent by email and are not stored by the plugin. Rate limiting uses a keyed hash of the connection IP address and temporary counters with a one-hour expiration.

== Installation ==

1. Install and activate the plugin.
2. Open the contact form settings under Settings. Enter your recipient, sender, and SMTP credentials. Choose implicit TLS on port 465 or STARTTLS on port 587.
3. Save the settings and send a test message.
4. Add the contact form block to a public page. Exclude the page from full-page or CDN caching so form tokens and submission feedback stay current.

== Changelog ==

= 1.2.1 =
* Reject number-only messages on the server and show a localized validation message.
* Send form and test messages through a dedicated instance of the PHPMailer bundled with WordPress.
* Store the latest delivery status without raw SMTP error text.

= 1.2.0 =
* Added SMTP configuration, a test email, and delivery status.
