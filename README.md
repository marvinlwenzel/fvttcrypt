## I can not imagine anyone else needing this. 

This module implements [Caddy](https://caddyserver.com/)/[Caddy GH](https://github.com/caddyserver/caddy) `http.authentication.hashes` as per [Caddy Module Namespaces](https://caddyserver.com/docs/extending-caddy/namespaces). 

[FoundryVTT](https://foundryvtt.com/) - some web app, for our purposes - has rudimentary user management - including storing hashed password. They use a pbkdf2 and sha512 based approach. I want a basic auth secured web server where my users use the same passwords for both my web server as well as the Foundry server. Caddy seems extensible, now we are here.

Foundrys password storage does not have an official API. Therefore this is **unstable**, **experimental**, **not intended** and **_generally a bad idea_**. Not enough to stop me, tho.

*As of developing this, while the interfaces exist, there is no functionality within caddy to actually use anything other than bcrypt, even if a `http.authentication.hashes` complient module is loaded. So this project also motivated a PR on Caddy itself.*