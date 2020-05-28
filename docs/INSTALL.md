# GoCD LDAP/AD Authorization Plugin

The plugin needs to be configured with authorization configurations in order to allow users access to GoCD.

Table of Contents
=================

  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Configuration](#configuring-the-ldap-plugin)
  * [Example](EXAMPLES.md)

## Prerequisites

* GoCD server version **19.2.0** or higher.

## Installation

* Copy the file `build/libs/gocd-ldap-authorization-plugin-VERSION.jar` to the GoCD server under `${GO_SERVER_DIR}/plugins/external` and restart the server.
* The `GO_SERVER_DIR` is usually `/var/lib/go-server` on **Linux** and `C:\Program Files\Go Server` on **Windows**.

## Configuring the plugin

1. Provide details of the Active Directory server to connect to via an [Authorization Configuration](AUTHORIZATION_CONFIGURATION.md).

2. Map Active Directory groups to GoCD roles via a [Plugin Role Configuration](PLUGIN_ROLE_CONFIGURATION.md).
