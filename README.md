Geoip-filter
============

Program to filter incoming SSH connections based on originating country.

Inspired by [ssh-geoip-filter](https://github.com/CristianCantoro/ssh-geoip-filter).

# How to use

In /etc/hosts.allow add

```
sshd: ALL: aclexec <path to geoip-filter binary> %a
``` 

and in /etc/hosts.deny add

``` 
sshd: ALL 
```

In geoip-filter.toml, remember to add your accepted country and/or ip into the whitelist.

It will allow all local ip connections to prevent being completely locked out.
