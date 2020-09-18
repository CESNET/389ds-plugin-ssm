# 389ds-plugin-ssm

Server Side Modification plugin

The plugin provides facilities for server-side updating entry based on
it's attribute values, modifiers DN and time.

## Compilation

```sh

$ apt-get install 389-ds-base-dev libnspr4-dev
$ make clean
$ make ssm
```

## Instalation
```sh
$ cp ssm.so /usr/lib/x86_64-linux-gnu/dirsrv/plugins
$ cat SSM.ldif | ldapmodify -H ldap://localhost -D "cn=Directory Manager" -W
$ cp udb.conf /etc/dirsrv/slapd-ldap/
$ systemctl restart dirsrv@ldap
```

## Configuration

Example of configuration file is in [udb.conf](udb.conf) and
[test.cfg](test.cfg). Syntax of conf file:

```conf
MODIFIED-ATTRIBUTE[,MODIFIED-ATTRIBUTE]
  FILTER↹OPERATION=TARGET-ATTRIBUTE=ACTION↹[OPERATION=TARGET-ATTRIBUTE=ACTION]
  FILTER↹OPERATION=TARGET-ATTRIBUTE=ACTION↹[OPERATION=TARGET-ATTRIBUTE=ACTION]
```

### MODIFIED-LDAP-ATTRIBUTE

Comma separated list of attributes which modification causes
ACTION. Any attribute can be addresed as '*'.

### FILTER

LDAP filter for limiting entries which should be subject of an ACTION.

### ↹

The TAB character serves as FILTER and OPERATION separator. Space is not permited.

### OPERATION

One of possilbe LDAP operations: `=` serves for REPLACE, `+` for ADD and `-` for DELETE.

### TARGET-ATTRIBUTE

Atribute which should be modified by an ACTION.

### ACTION

Posible actions are:

| ACTION         | Explanation |
| ---            | --- |
| `!opinit_time()` | Place timestamp of entry modification into TARGET-ATTRIBUTE |
| `!conn_dn()`     | Place modifiers DN into TARGET-ATTRIBUTE |
| `!concat(a, b, ...)` | Serialize strings a, b, ... and separate them by ` ` a space. If first argument is preceeded by ``$`` than it is interpreted as value of attribute. |
| `string1, string2` | Multiple strings is interpreted as multiple values assinged into TARGET-ATTRIBUTE |

### Examples

Every time ``entryStatus`` is modified update ``entryStatusTimestamp``
with modification timestamp and ``entryStatusModifier`` with modifiers DN:

```
entrystatus
  (objectclass=*)	=entrystatustimestamp=!opinit_time()	=entrystatusmodifier=!conn_dn()
```

Every time anything is changed on entry construct ``mail`` attribute:
```
*
  (uid=*)       mail=!concat(uid, @example.com)
```

Every time ``userPassword`` is updated record change timestamp in ``passwordTimestamp`` attribute:

```
userpassword
	(objectclass=*)	=passwordtimestamp=!opinit_time()
```

## Authors

This plugin was written by Milan Sova for Sun ONE Directory Server 4
around year 1999. At the time he was working for Faculty of Electrical
Engeneering of the Czech Technical University in Prague (FEL
CTU). Later he moved to CESNET.

The plugin was ported for 389 Directory Server 1.4 by Jiří Cejp from FEL CTU.

It was documented and published by [Jan Tomášek](https://github.com/semik) from CESNET.