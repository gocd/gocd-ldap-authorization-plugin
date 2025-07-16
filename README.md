# GoCD LDAP/AD Authorization Plugin

The GoCD LDAP/AD plugin implements the [Authorization Plugin](https://plugin-api.gocd.org/current/authorization/) endpoints to provide authentication and authorization services to GoCD. This plugin allows GoCD administrators to reuse LDAP/AD groups and map them to GoCD roles, reducing duplication and allowing management at a single location.

**Note:** This is not the same as the bundled [authentication plugin](https://github.com/gocd/gocd-ldap-authentication-plugin), and must be added to enable plugin roles. User can disable authentication plugin as both authentication and authorization services are handled by this LDAP/AD authorization plugin.

### Supported GoCD versions

The plugin version `5.x` supports GoCD version `22.1.0` and above.

Table of Contents
=================

  * [Building the code base](#building-the-code-base)
  * [Install and configure the plugin](docs/INSTALL.md)
    * [Prerequisites](docs/INSTALL.md#prerequisites)
    * [Installation](docs/INSTALL.md#installation)
    * [Configuration](docs/INSTALL.md#configuring-the-plugin)
        * [Authorization Configuration](docs/AUTHORIZATION_CONFIGURATION.md)
        * [Plugin Role Configuration](docs/PLUGIN_ROLE_CONFIGURATION.md)
  * [Examples](docs/EXAMPLES.md)
    * [Map users to a role using the UserGroupMembershipAttribute and GroupIdentifiers](docs/EXAMPLES.md#map-users-to-a-role-using-the-usergroupmembershipattribute-and-groupidentifiers)
    * [Map users to a role using the GroupMembershipFilter and GroupSearchBases](docs/EXAMPLES.md#map-users-to-a-role-using-the-groupmembershipfilter-and-groupsearchbases)
  * [Troubleshooting](docs/TROUBLESHOOT.md)

## Building the code base

To build the jar, run `./gradlew clean check assemble`

## License

```plain
Copyright 2022 Thoughtworks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
