# GoCD LDAP/AD Authorization Plugin

The GoCD LDAP/AD plugin implements the [Authorization Plugin](https://plugin-api.gocd.org/current/authorization/) endpoints to provide authentication and authorization services to GoCD. This plugin allows GoCD administrators to reuse LDAP/AD groups and map them to GoCD roles, reducing duplication and allowing management at a single location.

**Note:** This is not the same as the bundled [authentication plugin](https://github.com/gocd/gocd-ldap-authentication-plugin), and must be added to enable plugin roles. User can disable authentication plugin as both authentication and authorization services are handled by this LDAP/AD authorization plugin.

### Supported GoCD versions

The plugin version `3.0.0` supports GoCD version `19.2.0` and above. The plugin is upgraded to version 2 of the authorization extension to support [Access Token](https://docs.gocd.org/current/configuration/access_tokens.html) based API access.

Table of Contents
=================

  * [Building the code base](#building-the-code-base)
  * [Install and configure the plugin](docs/INSTALL.md)
  * [Troubleshooting](docs/TROUBLESHOOT.md)

## Building the code base

To build the jar, run `./gradlew clean check assemble`

## License

```plain
Copyright 2020 ThoughtWorks, Inc.

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
