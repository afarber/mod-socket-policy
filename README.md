mod-socket-policy
=================

Apache module for serving socket policy files for ActionScript applications 

ActionScript applications (Adobe Flash and Apache Flex) utilizing Socket and XMLSocket connections require special socket policy file served from the destination site.

This is done this way, so that for a example a malicious Flash banner can not connect to the SMTP port of the server hosting it - and send SPAM mails.

Some socket policy scripts found on the net are vulnerable to DOS attacks (because they use accept() on a blocking socket and try to serve only 1 client at a time) and even remote exploits (because they run as root and read data from clients).

This project provides an Apache module (2 versions are offered: in C or Perl) and (as alternative - for a quick run on Windows or Linux) a simple but robust Perl-script for serving socket policy file without these problems. 
